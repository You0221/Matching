import difflib
from typing import List, Dict, Optional

class DifflibMatcher:
    """
    将文件划分为行范围
    """

    def __init__(self, epsilon: int = 3):
        self.EPSILON = epsilon  # 允许最大行偏移

    def _get_diff_opcodes(self, parent_lines: List[str], child_lines: List[str]) -> List[Dict]:
        """
        获取diff操作码
        """
        matcher = difflib.SequenceMatcher(None, parent_lines, child_lines, autojunk=False)
        opcodes = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            parent_start = i1 + 1
            parent_end = i2
            child_start = j1 + 1
            child_end = j2

            opcodes.append({
                'tag': tag,
                'parent_range': (parent_start, parent_end),
                'child_range': (child_start, child_end),
                'parent_line_count': i2 - i1,
                'child_line_count': j2 - j1
            })

        return opcodes

    def _find_opcode_for_line(self, line_number: int, opcodes: List[Dict],
                              is_parent: bool = True) -> Optional[Dict]:
        """
        查找给定行号所在的操作码
        """
        for opcode in opcodes:
            if is_parent:
                start, end = opcode['parent_range']
            else:
                start, end = opcode['child_range']

            if start <= line_number <= end:
                return opcode

        return None

    def location_based_match(self, parent_line: int, child_line: int,
                             opcodes: List[Dict]) -> bool:
        """
        预计算opcodes的位置匹配
        """
        if not opcodes:
            return parent_line == child_line

        # 找到父警告和子警告所在的操作码
        parent_opcode = self._find_opcode_for_line(parent_line, opcodes, is_parent=True)
        child_opcode = self._find_opcode_for_line(child_line, opcodes, is_parent=False)

        if not parent_opcode or not child_opcode: #寻找不到对应操作码
            return False

        # 检查是否在同一个操作码中
        if parent_opcode is not child_opcode:
            return False

        tag = parent_opcode['tag']
        parent_start, parent_end = parent_opcode['parent_range']
        child_start, child_end = parent_opcode['child_range']

        if tag == 'delete' or tag == 'insert':
            return False
        else:  #  equal/replace
            parent_offset = parent_line - parent_start
            child_offset = child_line - child_start
            offset_diff = abs(parent_offset - child_offset)

            if tag == 'equal':
                return offset_diff == 0
            return offset_diff <= self.EPSILON