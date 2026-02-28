import json
import os
import hashlib
from typing import List, Dict, Set, Tuple, Optional
import difflib
import re
import numpy as np
from scipy.optimize import linear_sum_assignment
from diff_matcher import DifflibMatcher
from Warning_group import WarningGrouper
class Matcher:

    def __init__(self, matching_threshold: int = 3, context_lines: int = 3,
                 snippet_similarity: float = 0.9, hash_size: int = 20):
        self.MATCHING_THRESHOLD = matching_threshold  # 位置匹配阈值
        self.CONTEXT_LINES = context_lines  # 片段匹配上下文行数
        self.SNIPPET_SIMILARITY = snippet_similarity  # 片段相似度阈值
        self.HASH_SIZE = hash_size  # 哈希匹配的token大小
        self.diff_matcher = DifflibMatcher(epsilon=3)


    def load_warnings(self, json_file_path: str) -> List[Dict]:
        """从Bandit JSON文件加载警告数据"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            warnings = []

            if 'results' in data:
                for result in data['results']:
                    warning = {
                        'filename': result.get('filename', ''),
                        'line_number': result.get('line_number', 0),
                        'issue_confidence': result.get('issue_confidence', ''),
                        'issue_severity': result.get('issue_severity', ''),
                        'issue_text': result.get('issue_text', ''),
                        'test_name': result.get('test_name', ''),
                        'test_id': result.get('test_id', ''),
                        'code': result.get('code', ''),
                        'unique_id': f"{result.get('filename', '')}:{result.get('line_number', 0)}:{result.get('test_id', '')}",
                        'col_offset': result.get('col_offset', 0),
                        'end_col_offset': result.get('end_col_offset', 0),
                        'line_range': result.get('line_range', []),
                        'issue_cwe': result.get('issue_cwe', {})
                    }
                    warnings.append(warning)

            print(f"从 {os.path.basename(json_file_path)} 加载了 {len(warnings)} 个警告")
            return warnings

        except Exception as e:
            print(f"加载文件 {json_file_path} 时出错: {e}")
            return []

    def extract_relative_path(self, full_path: str) -> str:
        version_patterns = [
            "ansible-2.19.0b1",
            "ansible-2.20.0rc2",
            "ansible-2.19.0",
            "ansible-2.18.1",
            "ansible-2.17.4rc1",
            "ansible-2.17.1rc1",
        ]

        for pattern in version_patterns:
            if pattern in full_path:
                idx = full_path.index(pattern) + len(pattern)
                relative_path = full_path[idx:].lstrip('\\/')
                return relative_path

        return os.path.basename(full_path)

    def is_same_file(self, path1: str, path2: str) -> bool:
        """判断是否为相同文件"""
        rel1 = self.extract_relative_path(path1)
        rel2 = self.extract_relative_path(path2)

        # 完全相同的路径
        if rel1 == rel2:
            return True

        # 规范化路径
        norm1 = rel1.replace('\\', '/').lower()
        norm2 = rel2.replace('\\', '/').lower()

        return norm1 == norm2

    def get_file_content(self, file_path: str) -> Optional[str]:
        """获取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except:
            return None

    # 精确匹配算法
    def exact_matching(self, alarm1: Dict, alarm2: Dict) -> bool:
        file1 = self.extract_relative_path(alarm1['filename'])
        file2 = self.extract_relative_path(alarm2['filename'])

        #判断是否是相同文件
        if not self.is_same_file(file1, file2):
            return False

        #判断是否是同类型警告
        if alarm1.get('test_id', '') != alarm2.get('test_id', ''):
            return False

        #判断是否相同行
        return alarm1.get('line_number', 0) == alarm2.get('line_number', 0)

    def find_exactly_matching_alarm(self, parent_alarm: Dict, child_alarms: List[Dict]) -> List[Dict]:
        """查找精确匹配的警告"""
        return [child for child in child_alarms if self.exact_matching(parent_alarm, child)]

    # 位置匹配算法（基于diff映射）
    def location_matching(self, parent_alarm: Dict, child_alarm: Dict,
                                             opcodes: List[Dict]) -> bool:
        """
        使用行范围划分后的的位置匹配算法
        """
        #检查是否为同一文件
        file1 = self.extract_relative_path(parent_alarm['filename'])
        file2 = self.extract_relative_path(child_alarm['filename'])

        if not self.is_same_file(file1, file2):
            return False

        #检查警告类型是否相同
        if parent_alarm.get('test_id', '') != child_alarm.get('test_id', ''):
            return False

        #使用opcodes进行位置匹配
        parent_line = parent_alarm.get('line_number', 0)
        child_line = child_alarm.get('line_number', 0)

        return self.diff_matcher.location_based_match(parent_line, child_line, opcodes)

    def location_matching_score(self, parent_alarm: Dict, child_alarm: Dict,
                                                   opcodes: List[Dict]) -> int:
        return 2 if self.location_matching(parent_alarm, child_alarm, opcodes) else 0

    # 基于代码片段的匹配算法
    def get_code_line(self, content: str, line_number: int) -> Optional[str]:
        """获取指定行号的代码行"""
        if not content:
            return None

        lines = content.split('\n')
        total_lines = len(lines)

        if line_number < 1 or line_number > total_lines:
            return None

        return lines[line_number - 1]

    def normalize_code(self, code: str) -> str:
        if not code:
            return ""

        # 1. 移除单行注释
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)

        # 2.移除多行注释
        code = re.sub(r"'''[\s\S]*?'''", '', code)
        code = re.sub(r'"""[\s\S]*?"""', '', code)

        # 3. 处理每行
        lines = code.split('\n')
        normalized_lines = []

        for line in lines:
            trimmed_line = line.strip()
            if trimmed_line:
                # 移除行内多余空格（多个空格变为一个）
                trimmed_line = re.sub(r'\s+', ' ', trimmed_line)
                normalized_lines.append(trimmed_line)

        # 4. 返回字符串
        return '\n'.join(normalized_lines)

    def calculate_similarity(self, snippet1: str, snippet2: str) -> float:
        """计算两个代码片段的相似度"""
        if not snippet1 or not snippet2:
            return 0.0

        norm1 = self.normalize_code(snippet1)
        norm2 = self.normalize_code(snippet2)

        if not norm1 or not norm2:
            return 0.0

        matcher = difflib.SequenceMatcher(None, norm1, norm2)
        return matcher.ratio()

    def get_line_alarm_snippet(self, alarm: Dict, content: str) -> Optional[str]:
        """从源代码中提取多行违规代码片段"""
        if not content:
            return None

        line_range = alarm.get('line_range', [])
        if not line_range:
            return None

        lines = content.split('\n')
        start_line = min(line_range) - 1
        end_line = max(line_range)

        if start_line < 0 or end_line > len(lines):
            return None

        # 提取多行代码
        snippet_lines = lines[start_line:end_line]

        return '\n'.join(snippet_lines)

    def snippet_matching(self, parent_alarm: Dict, child_alarm: Dict,
                               parent_content: str, child_content: str) -> bool:
        """基于代码片段的匹配算法"""
        # 1. 检查违规类型是否相同
        if parent_alarm.get('test_id', '') != child_alarm.get('test_id', ''):
            return False

        # 2. 检查是否同一文件
        file1 = self.extract_relative_path(parent_alarm['filename'])
        file2 = self.extract_relative_path(child_alarm['filename'])

        if not self.is_same_file(file1, file2):
            return False

        # 3. 提取代码片段
        if parent_alarm.get('line_range', []):
            parent_snippet = self.get_line_alarm_snippet(parent_alarm, parent_content)
        else:
            line_no = parent_alarm.get('line_number', 0)
            parent_snippet = self.get_code_line(parent_content, line_no)

        if child_alarm.get('line_range', []):
            child_snippet = self.get_line_alarm_snippet(child_alarm, child_content)
        else:
            line_no = child_alarm.get('line_number', 0)
            child_snippet = self.get_code_line(child_content, line_no)

        if not parent_snippet or not child_snippet:
            return False

        # 4. 比较片段
        if parent_snippet.strip() == child_snippet.strip():
            return True
        else:#相似度比较（可选）
            if self.calculate_similarity(parent_snippet, child_snippet) >= self.SNIPPET_SIMILARITY:
                return True
        return False

    def snippet_matching_score(self, parent_alarm: Dict, child_alarm: Dict,
                                     parent_content: str, child_content: str) -> int:
        """基于代码片段的匹配算法"""
        return 1 if self.snippet_matching(parent_alarm, child_alarm, parent_content, child_content) else 0

    # 基于哈希的匹配算法
    def _split_into_tokens(self, text: str) -> List[str]:
        """token分割"""
        if not text:
            return []
        # 无法得知是否可靠
        # 移除字符串字面量
        #text = re.sub(r'"[^"]*"', '"STRING"', text)
        #text = re.sub(r"'[^']*'", "'STRING'", text)

        # 移除数字字面量
        #text = re.sub(r'\b\d+\b', 'NUMBER', text)

        # 分割token
        tokens = []

        # 使用正则表达式
        pattern = r'''
            \b(?:def|class|if|else|elif|for|while|try|except|finally|with|import|from|as|
                return|yield|pass|break|continue|assert|raise|global|nonlocal|
                True|False|None|and|or|not|in|is)\b|  
            [a-zA-Z_]\w*|  
            \d+|  
            \S  
        '''

        for match in re.finditer(pattern, text, re.VERBOSE):
            token = match.group()
            if len(token) >= 1 or token in '=+-*/%&|^~<>!()[]{},.:;@':
                tokens.append(token)

        return tokens

    def _hash_first_tokens(self, text: str) -> str:
        """计算前N个token的哈希值"""
        tokens = self._split_into_tokens(text)

        if not tokens:
            return ""

        # 取前N个token，如果不足则取全部
        first_tokens = tokens[:self.HASH_SIZE]
        first_text = ' '.join(first_tokens)

        return hashlib.md5(first_text.encode()).hexdigest()

    def _hash_last_tokens(self, text: str) -> Optional[str]:
        """计算从第HASH_SIZE+1个token到末尾的哈希值"""
        tokens = self._split_into_tokens(text)

        if not tokens:
            return None

        # 取从第HASH_SIZE+1个到末尾的所有token
        if len(tokens) > self.HASH_SIZE:
            rest_tokens = tokens[self.HASH_SIZE:]
            rest_text = ' '.join(rest_tokens)
            return hashlib.md5(rest_text.encode()).hexdigest()
        else:
            return None

    def get_code_snippet(self, content: str, line_number: int) -> Optional[str]:
        """获取代码上下文"""
        if not content:
            return None

        lines = content.split('\n')
        total_lines = len(lines)

        if line_number < 1 or line_number > total_lines:
            return None

        start_line = max(1, line_number - self.CONTEXT_LINES)
        end_line = min(total_lines, line_number + self.CONTEXT_LINES)

        snippet_lines = lines[start_line - 1:end_line]

        # 移除共同缩进
        min_indent = float('inf')
        for line in snippet_lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                min_indent = min(min_indent, indent)

        normalized_lines = []
        for line in snippet_lines:
            if line.strip() and min_indent != float('inf') and len(line) >= min_indent:
                normalized_lines.append(line[min_indent:])
            else:
                normalized_lines.append(line)

        return '\n'.join(normalized_lines)

    def hash_matching(self, parent_alarm: Dict, child_alarm: Dict,
                            parent_content: str, child_content: str) -> bool:
        """基于哈希的匹配算法"""
        if parent_alarm.get('test_id', '') != child_alarm.get('test_id', ''):
            return False

        # 获取多行上下文
        parent_snippet = self.get_code_snippet(parent_content, parent_alarm.get('line_number', 0))
        child_snippet = self.get_code_snippet(child_content, child_alarm.get('line_number', 0))

        if not parent_snippet or not child_snippet:
            return False

        # 计算前后token的哈希值
        parent_first_hash = self._hash_first_tokens(parent_snippet)
        parent_last_hash = self._hash_last_tokens(parent_snippet)

        child_first_hash = self._hash_first_tokens(child_snippet)
        child_last_hash = self._hash_last_tokens(child_snippet)

        # 比较哈希值（只要有一个相同就认为匹配）
        if parent_first_hash == child_first_hash:
            return True

        if parent_last_hash is not None and child_last_hash is not None:
            if parent_last_hash == child_last_hash:
                return True

        return False

    def hungarian_matching(self, parent_alarms: List[Dict], child_alarms: List[Dict],
                                        parent_content: str, child_content: str,
                                        opcodes: List[Dict]) -> List[Tuple[Dict, Dict, int]]:
        """
        匈牙利匹配算法
        """
        if not parent_alarms or not child_alarms:
            return []

        n_parent = len(parent_alarms)
        n_child = len(child_alarms)

        # 初始化为-1（表示不匹配）
        score_matrix = np.full((n_parent, n_child), -1, dtype=int)

        # 预先提取路径和test_id
        parent_files = [self.extract_relative_path(pa['filename']) for pa in parent_alarms]
        child_files = [self.extract_relative_path(ca['filename']) for ca in child_alarms]
        parent_test_ids = [pa.get('test_id', '') for pa in parent_alarms]
        child_test_ids = [ca.get('test_id', '') for ca in child_alarms]

        # 计算每对警告的分数
        for i in range(n_parent):
            for j in range(n_child):
                # 检查是否为同一文件
                if not self.is_same_file(parent_files[i], child_files[j]):
                    continue

                # 检查测试ID是否相同
                if parent_test_ids[i] != child_test_ids[j]:
                    continue

                # 计算位置匹配分数
                location_score = self.location_matching_score(
                    parent_alarms[i], child_alarms[j], opcodes
                )

                # 计算片段匹配分数
                snippet_score = self.snippet_matching_score(
                    parent_alarms[i], child_alarms[j], parent_content, child_content
                )

                total_score = location_score + snippet_score

                if total_score > 0:
                    score_matrix[i, j] = total_score

        # 使用匈牙利算法找到最大权重匹配
        if np.all(score_matrix == -1):  # 没有匹配项
            return []

        cost_matrix = -score_matrix
        row_ind, col_ind = linear_sum_assignment(cost_matrix)

        # 收集匹配结果
        matches = []
        for i, j in zip(row_ind, col_ind):
            score = score_matrix[i, j]
            if score > 0:  # 只保留分数大于0的匹配
                matches.append((parent_alarms[i], child_alarms[j], score))

        return matches

    def is_file_changed(self, parent_file_path: str, child_file_path: str) -> bool:
        """
        检查文件是否被修改
        """
        # 检查文件是否存在
        if not os.path.exists(parent_file_path) or not os.path.exists(child_file_path):
            return True  # 文件不存在，视为已修改

        try:
            # 读取文件内容
            with open(parent_file_path, 'r', encoding='utf-8') as f:
                parent_content = f.read()

            with open(child_file_path, 'r', encoding='utf-8') as f:
                child_content = f.read()

            # 内容完全相同，文件未修改
            if parent_content == child_content:
                return False

            return True

        except Exception as e:
            print(f"检查文件修改状态出错 {parent_file_path} -> {child_file_path}: {e}")
            return True

    def match_warnings_between_versions(self, parent_warnings: List[Dict],
                                        child_warnings: List[Dict],
                                        parent_source_dir: str,
                                        child_source_dir: str) -> Dict[str, List[Dict]]:
        """匹配两个版本间的警告"""


        print(f"\n开始匹配: 父版本有 {len(parent_warnings)} 个警告, 子版本有 {len(child_warnings)} 个警告")

        parent_alarms = parent_warnings.copy()
        child_alarms = child_warnings.copy()

        parent_tracked_indices = set()
        child_tracked_indices = set()

        match_type_counts = {
            'exact': 0,
            'location': 0,
            'snippet': 0,
            'location_and_snippet': 0,
            'hash': 0
        }

        results = {
            'true_positives': [],
            'false_positives': [],
            'unmatched_parent': [],
            'new_origins': [],
            'match_stats': match_type_counts
        }

        # 按文件路径分组
        print("按文件路径分组...")
        file_groups = WarningGrouper.group_warnings(parent_alarms, child_alarms)
        print(f"  共创建了 {len(file_groups)} 个文件组")

        # 遍历每个文件匹配组
        print("\n处理文件组...")
        for file_key, group in file_groups.items():
            parent_warnings_in_file = group['parent']
            child_warnings_in_file = group['child']

            print(
                f"  文件组: {file_key} - 父警告: {len(parent_warnings_in_file)}, 子警告: {len(child_warnings_in_file)}")

            if child_warnings_in_file:  # CommonFile（有子警告）
                # 构建文件路径
                relative_path = file_key.replace('/', os.path.sep)
                parent_file_path = os.path.join(parent_source_dir, relative_path)
                child_file_path = os.path.join(child_source_dir, relative_path)

                # 检查文件是否存在
                parent_exists = os.path.exists(parent_file_path)
                child_exists = os.path.exists(child_file_path)

                if not parent_exists or not child_exists:
                    print(f"    文件不存在，跳过")
                    continue

                # 判断当前文件是否为未修改文件
                is_changed = self.is_file_changed(parent_file_path, child_file_path)

                # 获取文件内容（用于匹配）
                parent_content = self.get_file_content(parent_file_path)
                child_content = self.get_file_content(child_file_path)

                if not parent_content or not child_content:
                    print(f"    警告: 无法读取文件内容，跳过")
                    continue

                if not is_changed:  # 文件未修改
                    print(f"    文件未修改，进行精确匹配")
                    for pa in parent_warnings_in_file:
                        parent_idx = parent_alarms.index(pa)
                        if parent_idx in parent_tracked_indices:
                            continue

                        # 精确匹配
                        exact_matches = self.find_exactly_matching_alarm(pa, child_warnings_in_file)
                        if exact_matches:
                            # 找第一个未被跟踪的子警告
                            for child_match in exact_matches:
                                child_idx = child_alarms.index(child_match)
                                if child_idx not in child_tracked_indices:
                                    parent_tracked_indices.add(parent_idx)
                                    child_tracked_indices.add(child_idx)

                                    results['false_positives'].append({
                                        'parent_warning': pa,
                                        'child_warning': child_match,
                                        'match_type': 'exact',
                                    })
                                    match_type_counts['exact'] += 1
                                    break
                else:  # 文件已修改
                    print(f"    文件已修改，进行匈牙利匹配")
                    # 在文件组级别只计算一次diff操作码
                    parent_lines = parent_content.split('\n')
                    child_lines = child_content.split('\n')
                    opcodes = self.diff_matcher._get_diff_opcodes(parent_lines, child_lines)

                    # 执行匈牙利匹配，传入预计算的opcodes
                    hungarian_matches = self.hungarian_matching(
                        parent_warnings_in_file, child_warnings_in_file,
                        parent_content, child_content, opcodes
                    )

                    # 处理匈牙利匹配结果
                    for parent_match, child_match, score in hungarian_matches:
                        parent_idx = parent_alarms.index(parent_match)
                        child_idx = child_alarms.index(child_match)

                        if parent_idx in parent_tracked_indices or child_idx in child_tracked_indices:
                            continue

                        parent_tracked_indices.add(parent_idx)
                        child_tracked_indices.add(child_idx)

                        # 根据分数确定匹配类型
                        if score == 3:
                            match_type = 'location_and_snippet'
                            match_type_counts['location_and_snippet'] += 1
                        elif score == 2:
                            match_type = 'location'
                            match_type_counts['location'] += 1
                        elif score == 1:
                            match_type = 'snippet'
                            match_type_counts['snippet'] += 1
                        else:
                            continue  # 0分不记录

                        results['false_positives'].append({
                            'parent_warning': parent_match,
                            'child_warning': child_match,
                            'match_type': match_type,
                        })

        for file_key, group in file_groups.items():
            parent_warnings_in_file = group['parent']
            # 进行哈希匹配
            for pa in parent_warnings_in_file:
                parent_idx = parent_alarms.index(pa)
                if parent_idx in parent_tracked_indices:
                    continue

                # 在整个子警告集中进行哈希匹配
                self._hash_match_across_files(
                    pa, child_alarms, parent_source_dir, child_source_dir,
                    parent_tracked_indices, child_tracked_indices,
                    results, match_type_counts, parent_alarms
                )

        #收集所有未匹配的父警告作为true_positives
        for parent_idx, parent in enumerate(parent_alarms):
            if parent_idx not in parent_tracked_indices:
                results['true_positives'].append(parent)

        #收集所有未匹配的子警告作为新出现的警告
        for child_idx, child in enumerate(child_alarms):
            if child_idx not in child_tracked_indices:
                results['new_origins'].append(child)

        print(f"\n匹配完成: 精确={match_type_counts['exact']}, 仅位置={match_type_counts['location']}, "
              f"仅片段={match_type_counts['snippet']},位置与片段均匹配={match_type_counts['location_and_snippet']} "
              f"哈希={match_type_counts['hash']}")
        print(f"  匹配对: {len(results['false_positives'])}")

        return results

    def _hash_match_across_files(self, parent_warning: Dict, child_alarms: List[Dict],
                                 parent_source_dir: str, child_source_dir: str,
                                 parent_tracked_indices: Set, child_tracked_indices: Set,
                                 results: Dict, match_type_counts: Dict,
                                 parent_alarms: List[Dict]):
        """在整个子警告集中进行哈希匹配"""
        # 获取父警告的文件路径
        parent_filename = parent_warning['filename']
        parent_relative = self.extract_relative_path(parent_filename)
        parent_file_path = os.path.join(parent_source_dir, parent_relative)

        # 获取父文件内容
        parent_content = self.get_file_content(parent_file_path)
        if not parent_content:
            return

        # 在所有子警告中进行哈希匹配
        for child_warning in child_alarms:
            child_idx = child_alarms.index(child_warning)
            if child_idx in child_tracked_indices:
                continue

            # 获取子文件路径和内容
            child_filename = child_warning['filename']
            child_relative = self.extract_relative_path(child_filename)
            child_file_path = os.path.join(child_source_dir, child_relative)

            child_content = self.get_file_content(child_file_path)
            if not child_content:
                continue

            # 检查哈希匹配
            if self.hash_matching(parent_warning, child_warning, parent_content, child_content):
                parent_idx = parent_alarms.index(parent_warning)

                parent_tracked_indices.add(parent_idx)
                child_tracked_indices.add(child_idx)

                results['false_positives'].append({
                    'parent_warning': parent_warning,
                    'child_warning': child_warning,
                    'match_type': 'hash',
                })
                match_type_counts['hash'] += 1
                break  # 只匹配第一个找到的


