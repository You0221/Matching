from typing import Dict, List
import os

class WarningGrouper:

    @staticmethod
    def extract_relative_path(full_path: str) -> str:
        if not os.path.isabs(full_path) and ':' not in full_path:
            return full_path.replace('\\', '/')
        return os.path.basename(full_path)

    @staticmethod
    def group_warnings(parent_warnings: List[Dict], child_warnings: List[Dict]) -> Dict[str, Dict[str, List[Dict]]]:
        file_groups = {}
        # 处理父警告
        for pa in parent_warnings:
            # 优先使用 relative_path 字段
            file_key = pa.get('relative_path')
            if not file_key:
                file_key = WarningGrouper.extract_relative_path(pa['filename'])

            # 寻找已存在的组（基于相同文件）
            existing_key = None
            for key in file_groups.keys():
                if WarningGrouper.is_same_file(file_key, key):
                    existing_key = key
                    break
            if existing_key:
                file_groups[existing_key]['parent'].append(pa)
            else:
                file_groups[file_key] = {'parent': [pa], 'child': []}

        # 处理子警告
        for ca in child_warnings:
            child_key = ca.get('relative_path')
            if not child_key:
                child_key = WarningGrouper.extract_relative_path(ca['filename'])

            matching_key = None
            for key in file_groups.keys():
                if WarningGrouper.is_same_file(child_key, key):
                    matching_key = key
                    break
            if matching_key:
                file_groups[matching_key]['child'].append(ca)

        return file_groups

    @staticmethod
    def is_same_file(path1: str, path2: str) -> bool:
        """判断两个路径是否指向同一文件"""
        norm1 = path1.replace('\\', '/').lower()
        norm2 = path2.replace('\\', '/').lower()
        return norm1 == norm2


