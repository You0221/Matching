import ast
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum



class FixStatus(Enum):
    FIXED = "fixed"
    NON_FIX = "non_fix"
    UNKNOWN = "unknown"


@dataclass
class CodeContext:
    """代码上下文信息"""
    class_name: Optional[str] = None
    function_name: Optional[str] = None
    variable_name: Optional[str] = None
    start_line: int = -1
    end_line: int = -1
    node_type: str = ""  # FunctionDef, ClassDef, Assign, etc.


@dataclass
class DiffChange:
    """代码变更信息"""
    change_type: str  # 'add', 'delete', 'modify', 'move'
    old_start: int = -1
    old_end: int = -1
    new_start: int = -1
    new_end: int = -1
    content: str = ""
    hunk_old_start: int = -1
    hunk_old_end: int = -1
    hunk_new_start: int = -1
    hunk_new_end: int = -1


class ASTFixAnalyzer:
    def __init__(self):
        self.context_cache: Dict[str, Dict[int, CodeContext]] = {}

    def _parse_file(self, file_path: str) -> Optional[ast.AST]:
        """解析为AST"""
        try:
            if not os.path.exists(file_path):
                return None
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return ast.parse(content, filename=file_path)
        except (SyntaxError, UnicodeDecodeError) as e:
            print(f"解析文件 {file_path} 时出错: {e}")
            return None

    def _extract_context(self, tree: ast.AST, line_number: int) -> CodeContext:

        class Visitor(ast.NodeVisitor):
            def __init__(self, target_line):
                self.target_line = target_line
                self.current_class = None
                self.current_function = None
                self.best_match = None
                self.closest_distance = float('inf')

            def visit_ClassDef(self, node):
                # 检查当前行是否在此类定义内
                if node.lineno <= self.target_line <= (getattr(node, 'end_lineno', node.lineno)):
                    old_class = self.current_class
                    self.current_class = node.name
                    self.generic_visit(node)
                    if not self.best_match or abs(node.lineno - self.target_line) < self.closest_distance:
                        self.best_match = CodeContext(
                            class_name=self.current_class,
                            function_name=self.current_function,
                            start_line=node.lineno,
                            end_line=getattr(node, 'end_lineno', node.lineno),
                            node_type='ClassDef'
                        )
                        self.closest_distance = abs(node.lineno - self.target_line)
                    self.current_class = old_class
                else:
                    self.generic_visit(node)

            def visit_FunctionDef(self, node):
                # 检查当前行是否在此函数定义内
                if node.lineno <= self.target_line <= (getattr(node, 'end_lineno', node.lineno)):
                    old_function = self.current_function
                    self.current_function = node.name
                    self.generic_visit(node)
                    if not self.best_match or abs(node.lineno - self.target_line) < self.closest_distance:
                        self.best_match = CodeContext(
                            class_name=self.current_class,
                            function_name=self.current_function,
                            start_line=node.lineno,
                            end_line=getattr(node, 'end_lineno', node.lineno),
                            node_type='FunctionDef'
                        )
                        self.closest_distance = abs(node.lineno - self.target_line)
                    self.current_function = old_function
                else:
                    self.generic_visit(node)

            def visit_Assign(self, node):
                # 检查是否是变量赋值
                if node.lineno <= self.target_line <= (getattr(node, 'end_lineno', node.lineno)):
                    var_name = None
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            break
                        elif isinstance(target, ast.Attribute):
                            var_name = target.attr
                            break

                    if not self.best_match or abs(node.lineno - self.target_line) < self.closest_distance:
                        self.best_match = CodeContext(
                            class_name=self.current_class,
                            function_name=self.current_function,
                            variable_name=var_name,
                            start_line=node.lineno,
                            end_line=getattr(node, 'end_lineno', node.lineno),
                            node_type='Assign'
                        )
                        self.closest_distance = abs(node.lineno - self.target_line)
                self.generic_visit(node)

            def visit_Expr(self, node):
                # 检查表达式
                if node.lineno <= self.target_line <= (getattr(node, 'end_lineno', node.lineno)):
                    if not self.best_match or abs(node.lineno - self.target_line) < self.closest_distance:
                        self.best_match = CodeContext(
                            class_name=self.current_class,
                            function_name=self.current_function,
                            start_line=node.lineno,
                            end_line=getattr(node, 'end_lineno', node.lineno),
                            node_type='Expr'
                        )
                        self.closest_distance = abs(node.lineno - self.target_line)
                self.generic_visit(node)

        visitor = Visitor(line_number)
        visitor.visit(tree)

        return visitor.best_match or CodeContext()

    def locate_context(self, file_path: str, line_number: int) -> CodeContext:
        """
        定位警告的上下文（类、方法、字段）line2
        """
        cache_key = f"{file_path}:{line_number}"
        if cache_key in self.context_cache:
            return self.context_cache[cache_key].get(line_number, CodeContext())

        tree = self._parse_file(file_path)
        if not tree:
            return CodeContext()

        context = self._extract_context(tree, line_number)

        if cache_key not in self.context_cache:
            self.context_cache[cache_key] = {}
        self.context_cache[cache_key][line_number] = context

        return context

    def is_deleted(self, context: CodeContext, new_file_path: str) -> bool:
        """
        line3 判断类、方法、字段是否被删除
        """
        if not os.path.exists(new_file_path):
            return True

        new_tree = self._parse_file(new_file_path)
        if not new_tree:
            return True

        # 检查类是否被删除
        if context.class_name:
            class_visitor = ClassExistsVisitor(context.class_name)
            class_visitor.visit(new_tree)
            if not class_visitor.exists:
                return True

        # 检查函数是否被删除
        if context.function_name:
            func_visitor = FunctionExistsVisitor(context.function_name)
            func_visitor.visit(new_tree)
            if not func_visitor.exists:
                return True

        # 检查变量是否被删除
        if context.variable_name:
            var_visitor = VariableExistsVisitor(context.variable_name)
            var_visitor.visit(new_tree)
            if not var_visitor.exists:
                return True

        return False

    def same_range(self, warning_line: int, context: CodeContext) -> bool:
        """
        line6 判断警告是否在声明范围内
        """
        if not context.start_line or context.start_line == -1:
            return False

        return warning_line == context.start_line

    def is_declaration_modified(self, old_context: CodeContext, new_context: CodeContext,
                                old_file_path: str, new_file_path: str) -> bool:
        """
        line7 检查声明是否被修改
        """
        # 读取旧声明
        old_declaration = self._extract_declaration_code(old_file_path, old_context)
        if not old_declaration:
            return False

        # 读取新声明
        new_declaration = self._extract_declaration_code(new_file_path, new_context)
        if not new_declaration:
            return True  # 声明被删除

        # 比较声明代码
        return old_declaration.strip() != new_declaration.strip()

    def _extract_declaration_code(self, file_path: str, context: CodeContext) -> Optional[str]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            if context.start_line < 1 or context.start_line > len(lines):
                return None

            # 提取声明行
            if context.node_type in ['FunctionDef', 'ClassDef']:
                start = context.start_line - 1
                end = min(context.start_line, len(lines))
                declaration_lines = []

                for i in range(start, end):
                    declaration_lines.append(lines[i])
                    if ':' in lines[i]:
                        break

                return ''.join(declaration_lines)
            else:
                return lines[context.start_line - 1]
        except Exception as e:
            print(f"提取声明代码出错: {e}")
            return None

    def get_repair_scope(self, warning: Dict, context: CodeContext) -> Tuple[int, int]:
        """
        获取修复范围
        """
        start_line = warning.get('line_number', -1)
        end_line = warning.get('line_number', -1)

        # 如果有行范围
        if 'line_range' in warning and warning['line_range']:
            line_range = warning['line_range']
            start_line = min(line_range)
            end_line = max(line_range)

        # 如果是单行警告，范围从警告行到方法结束
        if start_line == end_line and context.end_line > 0:
            return (start_line, context.end_line)

        # 返回方法范围
        if context.start_line > 0 and context.end_line > 0:
            return (context.start_line, context.end_line)

        return (start_line, end_line)

    def analyze_diff_changes(self, old_file_path: str, new_file_path: str,
                             old_version_index: Optional[int] = None,
                             new_version_index: Optional[int] = None,
                             diff_content: Optional[str] = None) -> List[DiffChange]:
        """
        使用 Git Diff 分析两个文件之间的差异
        """
        changes = []
        # 优先使用直接传入的 diff 内容
        if diff_content is not None:
            relative_path = self.extract_relative_path(old_file_path)
            if relative_path:
                changes = self._parse_diff_string_for_file(diff_content, relative_path)
            return changes

        if old_version_index is not None and new_version_index is not None:
            # 获取项目根目录
            # 例如：D:\...\source_code\ansible\ansible-2.17.1rc1\lib\ansible\...
            source_base = os.path.dirname(os.path.dirname(old_file_path))  # .../source_code/project
            project_root = os.path.dirname(source_base)  # .../source_code
            relative_path = self.extract_relative_path(old_file_path)
            if not relative_path:
                return changes
            diff_dir = os.path.join(project_root, 'diffs')
            diff_filename = f"v{old_version_index}-v{new_version_index}.diff"
            diff_file_path = os.path.join(diff_dir, diff_filename)
            if os.path.exists(diff_file_path):
                changes = self._parse_diff_file_for_file(diff_file_path, relative_path)
            return changes
        print(f"fix分析diff失败")
        return changes

    def _parse_diff_string_for_file(self, diff_content: str, relative_path: str) -> List[DiffChange]:
        """
        解析 diff 字符串，提取指定文件的变更
        """
        import re
        changes = []
        # 分割成文件块
        diff_blocks = []
        current_block = []
        lines = diff_content.splitlines(keepends=True)
        in_file = False
        target_path_normalized = relative_path.replace('\\', '/')

        for line in lines:
            if line.startswith('diff --git'):
                if current_block:
                    diff_blocks.append(''.join(current_block))
                    current_block = []
                current_block.append(line)
                in_file = True
            elif in_file:
                current_block.append(line)
        if current_block:
            diff_blocks.append(''.join(current_block))

        # 找到目标文件的块
        target_block = None
        for block in diff_blocks:
            match = re.search(r'^diff --git a/(.+?) b/(.+?)$', block, re.MULTILINE)
            if match:
                b_path = match.group(2).replace('\\', '/')
                if b_path.endswith(target_path_normalized) or target_path_normalized in b_path:
                    target_block = block
                    break

        if not target_block:
            return changes

        # 解析文件块中的 hunk
        lines = target_block.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.startswith('@@'):
                match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
                if not match:
                    continue
                old_start = int(match.group(1))
                old_count = int(match.group(2)) if match.group(2) else 1
                new_start = int(match.group(3))
                new_count = int(match.group(4)) if match.group(4) else 1

                # 计算 hunk 的旧范围和新范围
                hunk_old_start = old_start
                hunk_old_end = old_start + old_count - 1
                hunk_new_start = new_start
                hunk_new_end = new_start + new_count - 1

                current_old_line = old_start
                current_new_line = new_start

                while i < len(lines) and not lines[i].startswith('@@'):
                    diff_line = lines[i]
                    i += 1
                    if diff_line.startswith('-') and not diff_line.startswith('--'):
                        changes.append(DiffChange(
                            change_type='delete',
                            old_start=current_old_line,
                            old_end=current_old_line,
                            content=diff_line[1:].strip(),
                            hunk_old_start=hunk_old_start,
                            hunk_old_end=hunk_old_end,
                            hunk_new_start=hunk_new_start,
                            hunk_new_end=hunk_new_end
                        ))
                        current_old_line += 1
                    elif diff_line.startswith('+') and not diff_line.startswith('++'):
                        changes.append(DiffChange(
                            change_type='add',
                            new_start=current_new_line,
                            new_end=current_new_line,
                            content=diff_line[1:].strip(),
                            hunk_old_start=hunk_old_start,
                            hunk_old_end=hunk_old_end,
                            hunk_new_start=hunk_new_start,
                            hunk_new_end=hunk_new_end
                        ))
                        current_new_line += 1
                    elif diff_line.startswith(' '):
                        current_old_line += 1
                        current_new_line += 1
        return changes

    def _parse_diff_file_for_file(self, diff_file_path: str, relative_path: str) -> List[DiffChange]:
        """
        解析 diff 文件，提取指定文件的变更
        """
        import re
        changes = []
        try:
            with open(diff_file_path, 'r', encoding='utf-8') as f:
                diff_content = f.read()
        except Exception:
            return changes

        # 分割成文件块
        diff_blocks = []
        current_block = []
        lines = diff_content.splitlines(keepends=True)
        in_file = False
        target_path_normalized = relative_path.replace('\\', '/')

        for line in lines:
            if line.startswith('diff --git'):
                if current_block:
                    diff_blocks.append(''.join(current_block))
                    current_block = []
                current_block.append(line)
                in_file = True
            elif in_file:
                current_block.append(line)
        if current_block:
            diff_blocks.append(''.join(current_block))

        # 找到目标文件的块
        target_block = None
        for block in diff_blocks:
            match = re.search(r'^diff --git a/(.+?) b/(.+?)$', block, re.MULTILINE)
            if match:
                b_path = match.group(2).replace('\\', '/')
                if b_path.endswith(target_path_normalized) or target_path_normalized in b_path:
                    target_block = block
                    break

        if not target_block:
            return changes

        # 解析文件块中的 hunk
        lines = target_block.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.startswith('@@'):
                match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
                if not match:
                    continue
                old_start = int(match.group(1))
                new_start = int(match.group(3))
                current_old_line = old_start
                current_new_line = new_start

                while i < len(lines) and not lines[i].startswith('@@'):
                    diff_line = lines[i]
                    i += 1
                    if diff_line.startswith('-') and not diff_line.startswith('--'):
                        changes.append(DiffChange(
                            change_type='delete',
                            old_start=current_old_line,
                            old_end=current_old_line,
                            content=diff_line[1:].strip()
                        ))
                        current_old_line += 1
                    elif diff_line.startswith('+') and not diff_line.startswith('++'):
                        changes.append(DiffChange(
                            change_type='add',
                            new_start=current_new_line,
                            new_end=current_new_line,
                            content=diff_line[1:].strip()
                        ))
                        current_new_line += 1
                    elif diff_line.startswith(' '):
                        current_old_line += 1
                        current_new_line += 1
        return changes

    def extract_relative_path(self, full_path: str) -> str:
        if not os.path.isabs(full_path) and ':' not in full_path:
            return full_path.replace('\\', '/')
        return os.path.basename(full_path)



    def is_all_deletions(self, changes: List[DiffChange], scope_start: int, scope_end: int) -> bool:
        """
        判断范围内是否只有代码删除
        """
        if not changes:
            return False

        overlapping_changes = [
            c for c in changes
            if ((c.old_start != -1 and c.old_end != -1 and
                 not (c.old_end < scope_start or c.old_start > scope_end)) or
                (c.new_start != -1 and c.new_end != -1 and
                 not (c.new_end < scope_start or c.new_start > scope_end)))
        ]

        if not overlapping_changes:
            return False

        return all(c.change_type == 'delete' for c in overlapping_changes)

    def has_field_modified(self, changes: List[DiffChange], field_name: str,
                           scope_start: int, scope_end: int) -> bool:
        """
        line21 检查字段是否被修改
        """
        if not field_name:
            return False

        scope_changes = [
            c for c in changes
            if ((c.old_start >= scope_start and c.old_end <= scope_end) or
                (c.new_start >= scope_start and c.new_end <= scope_end)) and
               field_name in c.content
        ]

        return len(scope_changes) > 0

    def has_overlap(self, changes: List[DiffChange], scope: Tuple[int, int]) -> bool:
        """
        /检查更改是否与修复范围重叠
        """
        scope_start, scope_end = scope

        for change in changes:
            # 检查旧版本范围重叠
            if (change.old_start != -1 and change.old_end != -1 and
                    not (change.old_end < scope_start or change.old_start > scope_end)):
                return True

            # 检查新版本范围重叠
            if (change.new_start != -1 and change.new_end != -1 and
                    not (change.new_end < scope_start or change.new_start > scope_end)):
                return True

        return False

    def classify_removed_warning(self, warning: Dict,
                                 old_file_path: str, new_file_path: str,
                                 diff_changes: List[DiffChange]) -> Tuple[FixStatus, str]:
        """
        主函数
        """
        # l2 定位上下文
        context = self.locate_context(old_file_path, warning['line_number'])

        # l3 检查上下文是否被删除
        if self.is_deleted(context, new_file_path):
            return FixStatus.NON_FIX, "上下文（类、方法、字段）被删除"

        # l6 检查警告是否在声明范围内
        if self.same_range(warning['line_number'], context):
            # l7 检查声明是否被修改
            new_context = self.locate_context(new_file_path, context.start_line)
            is_modified = self.is_declaration_modified(context, new_context,
                                                       old_file_path, new_file_path)
            if is_modified:
                return FixStatus.FIXED, "声明被修改"
            else:
                return FixStatus.NON_FIX, "声明未被修改"

        # l11 检查警告是否在方法范围内
        repair_scope = self.get_repair_scope(warning, context)
        overlapping_changes = [
            c for c in diff_changes
            if ((c.old_start <= repair_scope[1] and c.old_end >= repair_scope[0]) or
                (c.new_start <= repair_scope[1] and c.new_end >= repair_scope[0]))
        ]

        # l14 如果没有更改
        if not overlapping_changes:
            return FixStatus.NON_FIX, "修复范围内没有代码更改"

        # l16 如果只有删除操作
        if self.is_all_deletions(overlapping_changes, repair_scope[0], repair_scope[1]):
            # 收集这些删除变更所属的 hunk 范围
            hunk_ranges = set()
            for c in overlapping_changes:
                if c.hunk_old_start != -1:
                    hunk_ranges.add((c.hunk_old_start, c.hunk_old_end, c.hunk_new_start, c.hunk_new_end))
            # 检查这些 hunk 中是否有新增变更
            has_add_in_hunk = False
            for (hunk_old_start, hunk_old_end, hunk_new_start, hunk_new_end) in hunk_ranges:
                # 检查是否有任何 add 变更属于这个 hunk
                for c in diff_changes:
                    if c.change_type == 'add' and c.hunk_old_start == hunk_old_start and c.hunk_old_end == hunk_old_end:
                        has_add_in_hunk = True
                        break
                if has_add_in_hunk:
                    break
            if has_add_in_hunk:
                pass
            else:
                return FixStatus.NON_FIX, "修复范围内只有代码删除"

        # l19 如果是关于字段的警告
        if context.variable_name:
            # l22 检查字段是否被修改
            if self.has_field_modified(overlapping_changes, context.variable_name,
                                       repair_scope[0], repair_scope[1]):
                return FixStatus.FIXED, "相关字段被修改"
            else:
                return FixStatus.NON_FIX, "相关字段未被修改"

        # l25 单行警告，调整修复范围
        if warning.get('line_number', -1) == warning.get('line_number', -2):
            repair_scope = (warning['line_number'], context.end_line)

            # l26 检查调整后的范围是否有更改
            if not self.has_overlap(diff_changes, repair_scope):
                return FixStatus.NON_FIX, "调整后的修复范围内没有代码更改"

        # l29 默认标记为修复
        return FixStatus.FIXED, "默认，代码被修改"


class ClassExistsVisitor(ast.NodeVisitor):
    def __init__(self, class_name: str):
        self.class_name = class_name
        self.exists = False

    def visit_ClassDef(self, node):
        if node.name == self.class_name:
            self.exists = True
        self.generic_visit(node)


class FunctionExistsVisitor(ast.NodeVisitor):
    def __init__(self, function_name: str):
        self.function_name = function_name
        self.exists = False

    def visit_FunctionDef(self, node):
        if node.name == self.function_name:
            self.exists = True
        self.generic_visit(node)


class VariableExistsVisitor(ast.NodeVisitor):
    def __init__(self, variable_name: str):
        self.variable_name = variable_name
        self.exists = False

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == self.variable_name:
                self.exists = True
            elif isinstance(target, ast.Attribute) and target.attr == self.variable_name:
                self.exists = True
        self.generic_visit(node)

    def visit_Name(self, node):
        if node.id == self.variable_name and isinstance(node.ctx, ast.Store):
            self.exists = True
        self.generic_visit(node)