"""
数据加载和预处理模块
支持从UCI和Kaggle数据集加载钓鱼网站数据
"""
import pandas as pd
import numpy as np
import os
from pathlib import Path


class PhishingDataLoader:
    """钓鱼网站数据加载器"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        # 确保数据目录存在，训练脚本首次运行时不需要手动创建data文件夹。
        self.data_dir.mkdir(exist_ok=True)
    
    def load_uci_dataset(self, file_path=None):
        """
        加载UCI钓鱼网站数据集
        数据集包含30个特征
        """
        # 尝试多个可能的路径，兼容用户把UCI数据集放在不同目录下的情况。
        # 尝试多个可能的路径
        possible_paths = [
            file_path,
            self.data_dir / "phishing_uci.csv",
            self.data_dir / "phishing+websites" / "Training Dataset.arff",
            Path("phishing+websites/Training Dataset.arff"),
        ]
        
        # 找到第一个存在的文件
        actual_path = None
        for path in possible_paths:
            if path is None:
                continue
            if os.path.exists(path):
                actual_path = path
                break
        
        if actual_path is None:
            print("警告: UCI数据集文件不存在")
            print("请从 https://archive.ics.uci.edu/ml/datasets/Phishing+Websites 下载数据集")
            return None
        
        try:
            # ARFF是UCI数据集常见格式，需要通过scipy读取后再转换成DataFrame。
            # 如果是.arff文件，需要特殊处理
            if actual_path.suffix == '.arff':
                # 使用pandas读取arff文件（需要scipy）
                try:
                    from scipy.io import arff
                    data, meta = arff.loadarff(actual_path)
                    df = pd.DataFrame(data)
                    # 将字节字符串转换为普通字符串
                    for col in df.columns:
                        if df[col].dtype == object:
                            df[col] = df[col].str.decode('utf-8')
                except ImportError:
                    print("警告: 需要scipy库来读取.arff文件，请运行: pip install scipy")
                    return None
            else:
                df = pd.read_csv(actual_path)
            
            print(f"成功加载UCI数据集: {len(df)} 条记录, {len(df.columns)} 个特征")
            print(f"文件路径: {actual_path}")
            return df
        except Exception as e:
            print(f"加载UCI数据集时出错: {e}")
            return None
    
    def load_kaggle_dataset(self, file_path=None):
        """
        加载Kaggle钓鱼网站数据集
        数据集包含48个特征
        """
        # 优先读取Kaggle CSV数据集，这是本项目训练模型的主要数据来源。
        # 尝试多个可能的路径
        possible_paths = [
            file_path,
            self.data_dir / "phishing_kaggle.csv",
            self.data_dir / "archive" / "Phishing_Legitimate_full.csv",
            self.data_dir / "Phishing_Legitimate_full.csv",
            Path("archive/Phishing_Legitimate_full.csv"),
            Path("Phishing_Legitimate_full.csv"),
        ]
        
        # 找到第一个存在的文件
        actual_path = None
        for path in possible_paths:
            if path is None:
                continue
            if os.path.exists(path):
                actual_path = path
                break
        
        if actual_path is None:
            print("警告: Kaggle数据集文件不存在")
            print("请从 https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning 下载数据集")
            print("或放在以下位置之一:")
            print("  - data/phishing_kaggle.csv")
            print("  - archive/Phishing_Legitimate_full.csv")
            return None
        
        try:
            df = pd.read_csv(actual_path)
            
            # 将不同数据集的标签统一成label列，方便后续训练代码复用。
            # 处理标签列名称（Kaggle数据集使用CLASS_LABEL）
            if 'CLASS_LABEL' in df.columns and 'label' not in df.columns:
                df['label'] = df['CLASS_LABEL']
                # 如果CLASS_LABEL是字符串，转换为数值
                if df['label'].dtype == 'object':
                    df['label'] = df['label'].map({'legitimate': 0, 'phishing': 1, 'Legitimate': 0, 'Phishing': 1})
                # 删除id列（如果存在）
                if 'id' in df.columns:
                    df = df.drop(columns=['id'])
            
            print(f"成功加载Kaggle数据集: {len(df)} 条记录, {len(df.columns)} 个特征")
            print(f"文件路径: {actual_path}")
            return df
        except Exception as e:
            print(f"加载Kaggle数据集时出错: {e}")
            return None
    
    def create_synthetic_dataset(self, n_samples=1000):
        """
        创建合成数据集用于演示（当真实数据集不可用时）
        基于常见的钓鱼网站特征
        """
        # 固定随机种子，保证演示数据每次生成结果一致，便于复现实验。
        np.random.seed(42)
        
        # 定义特征
        features = {
            # URL特征
            'url_length': np.random.randint(20, 200, n_samples),
            'url_depth': np.random.randint(1, 10, n_samples),
            'has_ip': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
            'has_at_symbol': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'has_dash': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
            'has_underscore': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
            'has_redirect': np.random.choice([0, 1], n_samples, p=[0.85, 0.15]),
            'subdomain_count': np.random.randint(0, 5, n_samples),
            'domain_age_days': np.random.randint(0, 3650, n_samples),
            'https_used': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            
            # 网页特征
            'page_rank': np.random.uniform(0, 10, n_samples),
            'external_links': np.random.randint(0, 100, n_samples),
            'internal_links': np.random.randint(0, 200, n_samples),
            'form_count': np.random.randint(0, 10, n_samples),
            'iframe_count': np.random.randint(0, 5, n_samples),
            'popup_count': np.random.randint(0, 3, n_samples),
            'script_count': np.random.randint(0, 50, n_samples),
            'meta_refresh': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
            'favicon_external': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
            'ssl_cert_valid': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            
            # 内容特征
            'title_length': np.random.randint(10, 100, n_samples),
            'body_text_length': np.random.randint(100, 10000, n_samples),
            'image_count': np.random.randint(0, 50, n_samples),
            'link_text_ratio': np.random.uniform(0, 1, n_samples),
            'suspicious_keywords': np.random.randint(0, 10, n_samples),
            'typo_count': np.random.randint(0, 5, n_samples),
            'brand_mention': np.random.choice([0, 1], n_samples, p=[0.6, 0.4]),
            
            # 其他特征
            'dns_record_count': np.random.randint(1, 10, n_samples),
            'port_number': np.random.choice([80, 443, 8080, 8443], n_samples),
            'tld_type': np.random.choice([0, 1, 2], n_samples, p=[0.7, 0.2, 0.1]),  # 0=com, 1=org, 2=其他
        }
        
        df = pd.DataFrame(features)
        
        # 用特征组合生成模拟标签，只在真实开源数据集缺失时作为演示兜底。
        # 生成标签（基于特征组合的简单规则）
        phishing_score = (
            (df['has_ip'] * 2) +
            (df['has_at_symbol'] * 3) +
            (df['url_length'] > 100).astype(int) +
            (df['domain_age_days'] < 365).astype(int) +
            (df['https_used'] == 0).astype(int) +
            (df['ssl_cert_valid'] == 0).astype(int) +
            (df['suspicious_keywords'] > 3).astype(int) +
            (df['iframe_count'] > 2).astype(int) +
            (df['popup_count'] > 1).astype(int)
        )
        
        df['label'] = (phishing_score >= 3).astype(int)
        
        print(f"创建合成数据集: {len(df)} 条记录, {len(df.columns)} 个特征")
        print(f"钓鱼网站: {df['label'].sum()} ({df['label'].mean()*100:.1f}%)")
        print(f"正常网站: {(df['label']==0).sum()} ({(df['label']==0).mean()*100:.1f}%)")
        
        return df
    
    def preprocess_data(self, df, target_column='label'):
        """
        数据预处理
        """
        if df is None or df.empty:
            return None, None
        
        # 检查目标列是否存在
        if target_column not in df.columns:
            print(f"警告: 目标列 '{target_column}' 不存在")
            return None, None
        
        # 分离特征和标签，X用于训练模型，y是正常/钓鱼的监督学习目标。
        # 分离特征和标签
        X = df.drop(columns=[target_column], errors='ignore')
        y = df[target_column]
        
        # 处理缺失值
        X = X.fillna(X.mean(numeric_only=True))
        
        # 机器学习模型只能直接处理数值特征，因此把文本列转换为数值编码。
        # 确保所有特征都是数值型
        for col in X.columns:
            if X[col].dtype == 'object':
                try:
                    X[col] = pd.to_numeric(X[col], errors='coerce')
                except:
                    X[col] = X[col].astype('category').cat.codes
        
        X = X.fillna(0)
        
        print(f"预处理完成: 特征形状 {X.shape}, 标签形状 {y.shape}")
        
        return X, y
