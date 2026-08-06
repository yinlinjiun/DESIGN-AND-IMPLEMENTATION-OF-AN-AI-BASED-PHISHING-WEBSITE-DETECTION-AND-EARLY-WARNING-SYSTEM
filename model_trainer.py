"""
模型训练和评估模块
支持多种机器学习算法进行钓鱼网站检测
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
import joblib
import os
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns


class PhishingModelTrainer:
    """钓鱼网站检测模型训练器"""
    
    def __init__(self, model_dir="models"):
        self.model_dir = Path(model_dir)
        # 所有训练好的模型和标准化器统一保存到models目录，便于Web系统启动时加载。
        self.model_dir.mkdir(exist_ok=True)
        self.models = {}
        self.scaler = StandardScaler()
        self.best_model = None
        self.best_model_name = None
    
    def prepare_data(self, X, y, test_size=0.2, random_state=42):
        """准备训练和测试数据"""
        # stratify保持训练集和测试集中正常/钓鱼样本比例一致，避免评估结果偏移。
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # 标准化特征主要供逻辑回归、SVM、MLP使用，树模型仍使用原始特征。
        # 标准化特征
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_random_forest(self, X_train, y_train, n_estimators=100, max_depth=20, random_state=42):
        """训练随机森林模型"""
        print("\n训练随机森林模型...")
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1
        )
        model.fit(X_train, y_train)
        self.models['random_forest'] = model
        return model
    
    def train_gradient_boosting(self, X_train, y_train, n_estimators=100, learning_rate=0.1, random_state=42):
        """训练梯度提升模型"""
        print("\n训练梯度提升模型...")
        model = GradientBoostingClassifier(
            n_estimators=n_estimators,
            learning_rate=learning_rate,
            random_state=random_state
        )
        model.fit(X_train, y_train)
        self.models['gradient_boosting'] = model
        return model
    
    def train_logistic_regression(self, X_train, y_train, random_state=42):
        """训练逻辑回归模型"""
        print("\n训练逻辑回归模型...")
        model = LogisticRegression(random_state=random_state, max_iter=1000)
        model.fit(X_train, y_train)
        self.models['logistic_regression'] = model
        return model
    
    def train_svm(self, X_train, y_train, kernel='rbf', random_state=42):
        """训练SVM模型"""
        print("\n训练SVM模型...")
        model = SVC(kernel=kernel, random_state=random_state, probability=True)
        model.fit(X_train, y_train)
        self.models['svm'] = model
        return model
    
    def train_mlp(self, X_train, y_train, hidden_layers=(100, 50), random_state=42):
        """训练多层感知机模型"""
        print("\n训练多层感知机模型...")
        model = MLPClassifier(
            hidden_layer_sizes=hidden_layers,
            random_state=random_state,
            max_iter=500
        )
        model.fit(X_train, y_train)
        self.models['mlp'] = model
        return model
    
    def train_ensemble(self, X_train, y_train, random_state=42):
        """训练集成模型"""
        print("\n训练集成模型...")
        
        rf = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=random_state, n_jobs=-1)
        gb = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=random_state)
        lr = LogisticRegression(random_state=random_state, max_iter=1000)
        
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('gb', gb), ('lr', lr)],
            voting='soft'
        )
        ensemble.fit(X_train, y_train)
        self.models['ensemble'] = ensemble
        return ensemble
    
    def evaluate_model(self, model, X_test, y_test, model_name="模型"):
        """评估模型性能"""
        # 同时输出准确率、精确率、召回率和F1，避免只看准确率造成误判。
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        print(f"\n{model_name} 评估结果:")
        print(f"准确率 (Accuracy): {accuracy:.4f}")
        print(f"精确率 (Precision): {precision:.4f}")
        print(f"召回率 (Recall): {recall:.4f}")
        print(f"F1分数 (F1-Score): {f1:.4f}")
        
        print(f"\n混淆矩阵:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        print(f"\n分类报告:")
        print(classification_report(y_test, y_pred, target_names=['正常', '钓鱼']))
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': cm,
            'y_pred': y_pred,
            'y_pred_proba': y_pred_proba
        }
    
    def train_all_models(self, X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test):
        """训练所有模型并评估"""
        results = {}
        
        # 对比多种模型，最后根据F1分数选择最适合钓鱼识别任务的模型。
        # 训练所有模型
        self.train_random_forest(X_train, y_train)
        self.train_gradient_boosting(X_train, y_train)
        self.train_logistic_regression(X_train_scaled, y_train)
        self.train_svm(X_train_scaled, y_train)
        self.train_mlp(X_train_scaled, y_train)
        self.train_ensemble(X_train, y_train)
        
        # 评估所有模型
        results['random_forest'] = self.evaluate_model(
            self.models['random_forest'], X_test, y_test, "随机森林"
        )
        results['gradient_boosting'] = self.evaluate_model(
            self.models['gradient_boosting'], X_test, y_test, "梯度提升"
        )
        results['logistic_regression'] = self.evaluate_model(
            self.models['logistic_regression'], X_test_scaled, y_test, "逻辑回归"
        )
        results['svm'] = self.evaluate_model(
            self.models['svm'], X_test_scaled, y_test, "SVM"
        )
        results['mlp'] = self.evaluate_model(
            self.models['mlp'], X_test_scaled, y_test, "多层感知机"
        )
        results['ensemble'] = self.evaluate_model(
            self.models['ensemble'], X_test, y_test, "集成模型"
        )
        
        # 钓鱼检测更关注风险样本识别能力，因此用F1作为综合选择指标。
        # 选择最佳模型
        best_f1 = 0
        for name, result in results.items():
            if result['f1'] > best_f1:
                best_f1 = result['f1']
                self.best_model_name = name
                self.best_model = self.models[name]
        
        print(f"\n最佳模型: {self.best_model_name} (F1分数: {best_f1:.4f})")
        
        return results
    
    def save_model(self, model, model_name, scaler=None):
        """保存模型"""
        # 使用joblib保存sklearn模型，Web应用启动时可以直接反序列化加载。
        model_path = self.model_dir / f"{model_name}.pkl"
        joblib.dump(model, model_path)
        print(f"模型已保存到: {model_path}")
        
        if scaler:
            scaler_path = self.model_dir / f"{model_name}_scaler.pkl"
            joblib.dump(scaler, scaler_path)
            print(f"标准化器已保存到: {scaler_path}")
    
    def load_model(self, model_name):
        """加载模型"""
        model_path = self.model_dir / f"{model_name}.pkl"
        if os.path.exists(model_path):
            model = joblib.load(model_path)
            print(f"模型已从 {model_path} 加载")
            return model
        else:
            print(f"模型文件 {model_path} 不存在")
            return None
    
    def predict(self, X, model_name=None, use_scaler=False):
        """使用模型进行预测"""
        # 支持指定模型预测，也支持默认使用训练阶段选出的best_model。
        if model_name is None:
            model = self.best_model
        else:
            model = self.models.get(model_name) or self.load_model(model_name)
        
        if model is None:
            raise ValueError("没有可用的模型")
        
        if use_scaler:
            X = self.scaler.transform(X)
        
        predictions = model.predict(X)
        probabilities = model.predict_proba(X) if hasattr(model, 'predict_proba') else None
        
        return predictions, probabilities
    
    def plot_feature_importance(self, model, feature_names, top_n=20, save_path=None):
        """绘制特征重要性"""
        # 特征重要性图用于解释模型关注哪些指标，也适合放入论文和答辩展示。
        if not hasattr(model, 'feature_importances_'):
            print("该模型不支持特征重要性分析")
            return
        
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]
        
        plt.figure(figsize=(10, 8))
        plt.title(f"Top {top_n} 特征重要性")
        plt.barh(range(top_n), importances[indices])
        plt.yticks(range(top_n), [feature_names[i] for i in indices])
        plt.xlabel('重要性')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"特征重要性图已保存到: {save_path}")
        else:
            plt.show()
