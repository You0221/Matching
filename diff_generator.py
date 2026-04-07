import os
import re
from typing import Optional
from fix_analyzer import ASTFixAnalyzer  # 启用 fix_analyzer

class DiffGenerator:
    """为消失的警告生成代码差异并保存到文件"""

    # 用于解析 diff 文件的正则表达式
    DIFF_FILE_PATTERN = re.compile(r'^diff --git a/(.+?) b/(.+?)$', re.MULTILINE)
    HUNK_HEADER_PATTERN = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', re.MULTILINE)

    def __init__(self, output_dir: str, context_lines: int = 5):

        self.output_dir = output_dir
        self.context_lines = context_lines
        self.analyzer = ASTFixAnalyzer()  # 用于获取修复范围

    def generate_diff(self,
                      relative_path: str,
                      line_number: int,
                      unique_id: str,
                      old_source_dir: str,
                      new_source_dir: str,
                      old_version: str,
                      new_version: str,
                      old_version_index: Optional[int] = None,
                      new_version_index: Optional[int] = None,
                      warning_dict: Optional[dict] = None) -> Optional[str]:

        #获取修复范围
        repair_scope = self._get_repair_scope(relative_path, line_number, old_source_dir, warning_dict)
        if repair_scope is None:
            repair_scope = (max(1, line_number - self.context_lines),
                            line_number + self.context_lines)

        # 构造 git diff 文件路径
        # old_source_dir 格式: .../source_code/<project>/<version>
        project_root = os.path.dirname(old_source_dir)  # .../source_code/<project>
        diff_dir = os.path.join(project_root, 'diffs')
        diff_filename = f"v{old_version_index}-v{new_version_index}.diff"
        git_diff_path = os.path.join(diff_dir, diff_filename)

        if not os.path.exists(git_diff_path):
            return None

        try:
            with open(git_diff_path, 'r', encoding='utf-8') as f:
                full_diff = f.read()
        except Exception:
            return None

        file_diff = self._extract_file_diff(full_diff, relative_path)
        if not file_diff:
            return None

        # 提取与修复范围重叠的 hunk
        start_line, end_line = repair_scope
        snippet_diff = self._extract_relevant_hunks(file_diff, relative_path, start_line, end_line)
        if not snippet_diff:
            snippet_diff = self._extract_file_header(file_diff)

        if not snippet_diff or not snippet_diff.strip():
            return None

        # 保存 diff 片段
        safe_id = unique_id.replace(':', '_').replace('/', '_').replace('\\', '_')
        diff_dir_out = os.path.join(self.output_dir, 'diffs')
        os.makedirs(diff_dir_out, exist_ok=True)
        diff_file = os.path.join(diff_dir_out, f"{safe_id}.diff")
        with open(diff_file, 'w', encoding='utf-8') as f:
            f.write(snippet_diff)

        return diff_file

    def _get_repair_scope(self, relative_path: str, line_number: int,
                          old_source_dir: str, warning_dict: Optional[dict]) -> Optional[tuple]:
        """
        获取修复范围
        """
        old_file_path = os.path.join(old_source_dir, relative_path)
        if not os.path.exists(old_file_path):
            return None

        try:
            context = self.analyzer.locate_context(old_file_path, line_number)
            temp_warning = {'line_number': line_number}
            if warning_dict and 'line_range' in warning_dict:
                temp_warning['line_range'] = warning_dict['line_range']
            start, end = self.analyzer.get_repair_scope(temp_warning, context)
            if start != -1 and end != -1:
                return (start, end)
        except Exception as e:
            pass
        return None

    def _extract_file_diff(self, full_diff: str, relative_path: str) -> Optional[str]:
        """
        从完整 diff 中提取指定文件的 diff 块
        """
        lines = full_diff.splitlines(keepends=True)
        file_blocks = []
        current_block = []
        in_file = False
        target_path_normalized = relative_path.replace('\\', '/')

        for line in lines:
            if line.startswith('diff --git'):
                if current_block:
                    file_blocks.append(''.join(current_block))
                    current_block = []
                current_block.append(line)
                in_file = True
                continue

            if in_file:
                current_block.append(line)

        if current_block:
            file_blocks.append(''.join(current_block))

        for block in file_blocks:
            match = self.DIFF_FILE_PATTERN.search(block)
            if not match:
                continue
            b_path = match.group(2).replace('\\', '/')
            if b_path.endswith(target_path_normalized) or target_path_normalized in b_path:
                return block

        return None

    def _extract_relevant_hunks(self, file_diff: str, relative_path: str,
                                start_line: int, end_line: int) -> Optional[str]:
        """
        从文件 diff 中提取与指定行范围重叠的 hunk 块
        """
        lines = file_diff.splitlines(keepends=True)
        header_lines = []
        hunk_start_indices = []
        for i, line in enumerate(lines):
            if line.startswith('@@'):
                hunk_start_indices.append(i)
                break
        if not hunk_start_indices:
            return None
        header_end = hunk_start_indices[0]
        header_lines = lines[:header_end]

        relevant_hunks = []
        current_hunk_lines = []
        for i, line in enumerate(lines[header_end:], start=header_end):
            if line.startswith('@@'):
                if current_hunk_lines:
                    hunk_text = ''.join(current_hunk_lines)
                    if self._hunk_overlaps_range(hunk_text, start_line, end_line):
                        relevant_hunks.append(hunk_text)
                    current_hunk_lines = []
                current_hunk_lines.append(line)
            else:
                current_hunk_lines.append(line)
        if current_hunk_lines:
            hunk_text = ''.join(current_hunk_lines)
            if self._hunk_overlaps_range(hunk_text, start_line, end_line):
                relevant_hunks.append(hunk_text)

        if not relevant_hunks:
            return None

        return ''.join(header_lines) + ''.join(relevant_hunks)

    def _hunk_overlaps_range(self, hunk_text: str, start_line: int, end_line: int) -> bool:
        """
        判断 hunk 覆盖的旧版本行范围是否与 [start_line, end_line] 有重叠
        """
        match = self.HUNK_HEADER_PATTERN.search(hunk_text)
        if not match:
            return False
        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) else 1
        old_end = old_start + old_count - 1
        return not (old_end < start_line or old_start > end_line)

    def _extract_file_header(self, file_diff: str) -> str:
        """
        提取文件头（diff --git 和 ---/+++ 行）
        """
        lines = file_diff.splitlines(keepends=True)
        header_lines = []
        for line in lines:
            if line.startswith('diff --git') or line.startswith('---') or line.startswith('+++'):
                header_lines.append(line)
            elif line.startswith('@@'):
                break
        return ''.join(header_lines)