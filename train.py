"""
模型训练脚本
用于训练钓鱼网站检测模型
"""
from data_loader import PhishingDataLoader
from model_trainer import PhishingModelTrainer
import pandas as pd
import numpy as np


def main():
    """主训练函数"""
    # 训练入口按步骤串联数据加载、预处理、模型训练、模型保存和特征分析。
    print("=" * 60)
    print("钓鱼网站检测模型训练")
    print("=" * 60)
    
    # 初始化数据加载器
    loader = PhishingDataLoader(data_dir="data")
    
    # 尝试加载数据集
    print("\n1. 加载数据集...")
    df = None
    
    # 优先使用开源Kaggle数据集；如果缺失，再尝试UCI数据集。
    # 优先尝试加载Kaggle数据集（因为用户已经下载了）
    df = loader.load_kaggle_dataset()
    
    # 如果Kaggle数据集不存在，尝试UCI数据集
    if df is None:
        df = loader.load_uci_dataset()
    
    # 合成数据只作为演示兜底，正式训练仍应优先使用开源真实数据集。
    # 如果都不存在，创建合成数据集用于演示
    if df is None:
        print("\n未找到真实数据集，创建合成数据集用于演示...")
        df = loader.create_synthetic_dataset(n_samples=2000)
        # 保存合成数据集
        df.to_csv("data/phishing_synthetic.csv", index=False)
        print("合成数据集已保存到 data/phishing_synthetic.csv")
    
    if df is None or df.empty:
        print("错误: 无法加载或创建数据集")
        return
    
    # 将原始数据转成模型可训练的数值特征X和标签y。
    # 数据预处理
    print("\n2. 数据预处理...")
    X, y = loader.preprocess_data(df, target_column='label')
    
    if X is None or y is None:
        print("错误: 数据预处理失败")
        return
    
    print(f"数据集统计:")
    print(f"  总样本数: {len(X)}")
    print(f"  特征数: {len(X.columns)}")
    print(f"  钓鱼网站: {y.sum()} ({y.mean()*100:.1f}%)")
    print(f"  正常网站: {(y==0).sum()} ({(y==0).mean()*100:.1f}%)")
    
    # 初始化模型训练器
    print("\n3. 初始化模型训练器...")
    trainer = PhishingModelTrainer(model_dir="models")
    
    # 按8:2划分训练集和测试集，并额外生成标准化后的版本供部分模型使用。
    # 准备训练数据
    print("\n4. 准备训练数据...")
    X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test = trainer.prepare_data(
        X, y, test_size=0.2, random_state=42
    )
    
    print(f"训练集: {len(X_train)} 样本")
    print(f"测试集: {len(X_test)} 样本")
    
    # 统一训练多个候选模型，再由训练器根据评估结果挑选最佳模型。
    # 训练所有模型
    print("\n5. 训练模型...")
    results = trainer.train_all_models(
        X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test
    )
    
    # 保存最佳模型后，app.py启动时会自动从models目录加载并用于在线检测。
    # 保存最佳模型
    print("\n6. 保存最佳模型...")
    if trainer.best_model and trainer.best_model_name:
        trainer.save_model(
            trainer.best_model, 
            trainer.best_model_name,
            scaler=trainer.scaler if hasattr(trainer, 'scaler') else None
        )
    
    # 随机森林等树模型支持特征重要性，可用于说明模型判断依据。
    # 绘制特征重要性（如果支持）
    print("\n7. 分析特征重要性...")
    if trainer.best_model and hasattr(trainer.best_model, 'feature_importances_'):
        try:
            trainer.plot_feature_importance(
                trainer.best_model,
                list(X.columns),
                top_n=20,
                save_path="models/feature_importance.png"
            )
        except Exception as e:
            print(f"绘制特征重要性时出错: {e}")
    
    print("\n" + "=" * 60)
    print("训练完成！")
    print("=" * 60)
    print(f"\n最佳模型: {trainer.best_model_name}")
    if trainer.best_model_name in results:
        result = results[trainer.best_model_name]
        print(f"准确率: {result['accuracy']:.4f}")
        print(f"精确率: {result['precision']:.4f}")
        print(f"召回率: {result['recall']:.4f}")
        print(f"F1分数: {result['f1']:.4f}")
    print("\n模型文件保存在 models/ 目录下")
    print("可以使用 python app.py 启动Web应用进行检测")


if __name__ == "__main__":
    main()
