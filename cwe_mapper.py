import os
import pandas as pd
from typing import Dict, Optional, Tuple


class CWEMapper:

    def __init__(self, mapping_dir: str):
        self.mapping_dir = mapping_dir
        self._mapping: Dict[Tuple[str, str], str] = {}  # (tool, rule_id) -> CWE-xxx
        self._load_all_mappings()

    def _load_all_mappings(self):
        """加载每个工具的映射文件"""
        tool_configs = {
            'bandit': {
                'file': 'merged_bandit_report.xlsx',
                'rule_col': 'test_id',
                'cwe_col': 'issue_cwe_id'
            },
            'codeql': {
                'file': 'merged_codeql_Python_report.xlsx',
                'rule_col': 'ruleId',
                'cwe_col': 'cwe'
            },
            'horusec': {
                'file': 'horusec_all_unique_rules.xlsx',
                'rule_col': 'rule_id',
                'cwe_col': 'extracted_cwe'
            },
            'pylint': {
                'file': 'merged_pylint_report.xlsx',
                'rule_col': 'symbol',
                'cwe_col': 'CWE'
            },
            'semgrep': {
                'file': 'python-semgrep-merged.xlsx',
                'rule_col': 'check_id',
                'cwe_col': 'cwe'
            }
        }

        for tool, cfg in tool_configs.items():
            file_path = os.path.join(self.mapping_dir, cfg['file'])
            if not os.path.exists(file_path):
                print(f"警告: 映射文件不存在 {file_path}")
                continue
            try:
                df = pd.read_excel(file_path)
                if cfg['rule_col'] not in df.columns or cfg['cwe_col'] not in df.columns:
                    print(f"警告: 文件 {file_path} 缺少必要列 {cfg['rule_col']} 或 {cfg['cwe_col']}")
                    continue

                count = 0
                for _, row in df.iterrows():
                    rule_id = str(row[cfg['rule_col']]).strip()
                    cwe_raw = row[cfg['cwe_col']]
                    if pd.isna(cwe_raw):
                        continue
                    cwe = self._normalize_cwe(cwe_raw)
                    if cwe:
                        self._mapping[(tool, rule_id)] = cwe
                        count += 1
                print(f"加载 {tool} 映射: {count} 条")
            except Exception as e:
                print(f"加载文件 {file_path} 时出错: {e}")

    def _normalize_cwe(self, cwe_raw) -> Optional[str]:
        """转换为 CWE-数字"""
        if isinstance(cwe_raw, (int, float)):
            return f"CWE-{int(cwe_raw)}"
        if isinstance(cwe_raw, str):
            cwe_str = cwe_raw.strip()
            if cwe_str.startswith('CWE-'):
                return cwe_str.split(',')[0].strip()
            if cwe_str.isdigit():
                return f"CWE-{cwe_str}"
        return None

    def get_cwe(self, tool: str, rule_id: str) -> Optional[str]:
        return self._mapping.get((tool, rule_id))