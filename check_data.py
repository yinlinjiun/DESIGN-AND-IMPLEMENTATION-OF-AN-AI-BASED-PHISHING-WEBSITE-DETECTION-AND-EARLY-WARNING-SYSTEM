"""
检查数据文件脚本
"""
import os
from pathlib import Path

data_dir = Path("data")
data_dir.mkdir(exist_ok=True)

print("检查数据目录...")
print(f"数据目录: {data_dir.absolute()}")

if data_dir.exists():
    files = list(data_dir.glob("*.csv"))
    if files:
        print(f"\n找到 {len(files)} 个CSV文件:")
        for f in files:
            size = f.stat().st_size / (1024 * 1024)  # MB
            print(f"  - {f.name} ({size:.2f} MB)")
    else:
        print("\n未找到CSV文件")
        print("请将数据集文件放在 data/ 目录下")
        print("支持的文件名:")
        print("  - phishing_uci.csv (UCI数据集)")
        print("  - phishing_kaggle.csv (Kaggle数据集)")
else:
    print("数据目录不存在")

