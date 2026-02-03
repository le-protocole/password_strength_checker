#  Password Strength Checker

> *"Not just code, but thinking"* - Comprehensive portfolio project with security focus

---

<!--  AUTO LANGUAGE SELECTOR -->
<div align="center">

##  Language Selection | 语言选择 | Sélection de langue | Хэл сонгох

### [🇺🇸 English](#-english--english) | [🇨🇳 中文](#-chinese--chinese) | [🇫🇷 Français](#-french--french) | [🇲🇳 Монгол](#-mongolian--mongolian)

</div>

---

## 🇺🇸 English {#-english--english}

A comprehensive cybersecurity project for analyzing **password strength, entropy, common weak patterns**, and demonstrating **secure password hashing (educational demo)**.

##  Features

### Core Features
- **Real-time Password Analysis** - Instant feedback on password strength
- **Security Criteria Checks** - Validates uppercase, lowercase, numbers, and special characters
- **Entropy Calculation** - Measures password complexity using information theory
- **Blacklist Checking** - Detects common/weak passwords and patterns
- **Secure Hashing** - SHA-256, bcrypt, and argon2 support

##  Quick Start

### Installation
```bash
cd password_strength_checker
pip install -r requirements.txt
```

### Running
**Interactive Mode:** `python main.py`  
**Demo Mode:** `python main.py demo`  
**Test Password:** `python main.py test "MyPassword123!"`  
**Web UI:** Open `web/index.html` in browser  
**Flask API:** `python app.py`

---

## 🇨🇳 中文 {#-chinese--chinese}

用于分析 **密码强度、熵值、常见弱密码模式**，并演示 **安全密码哈希（教学示例）** 的网络安全项目。

##  功能特点

### 核心功能
- **实时密码分析** - 立即反馈密码强度
- **安全标准检查** - 验证大小写字母、数字和特殊字符
- **熵值计算** - 使用信息论测量密码复杂度
- **黑名单检查** - 检测常见/弱密码和模式
- **安全哈希** - 支持 SHA-256、bcrypt 和 argon2

##  快速开始

### 安装
```bash
cd password_strength_checker
pip install -r requirements.txt
```

### 运行
**交互模式:** `python main.py`  
**演示模式:** `python main.py demo`  
**测试密码:** `python main.py test "MyPassword123!"`  
**网页界面:** 在浏览器中打开 `web/index.html`  
**Flask API:** `python app.py`

---

## 🇫🇷 Français {#-french--french}

Un projet de cybersécurité pour analyser **la robustesse des mots de passe**, leur **entropie**, les **schémas faibles courants**, et démontrer les **bonnes pratiques de hachage sécurisé**.

##  Caractéristiques

### Fonctionnalités principales
- **Analyse en temps réel** - Commentaires instantanés sur la force du mot de passe
- **Vérifications de sécurité** - Valide les majuscules, minuscules, chiffres et caractères spéciaux
- **Calcul d'entropie** - Mesure la complexité du mot de passe
- **Vérification de liste noire** - Détecte les mots de passe courants/faibles
- **Hachage sécurisé** - Support SHA-256, bcrypt et argon2

##  Démarrage rapide

### Installation
```bash
cd password_strength_checker
pip install -r requirements.txt
```

### Exécution
**Mode interactif:** `python main.py`  
**Mode démonstration:** `python main.py demo`  
**Tester un mot de passe:** `python main.py test "MyPassword123!"`  
**Interface Web:** Ouvrez `web/index.html` dans votre navigateur  
**API Flask:** `python app.py`

---

## 🇲🇳 Монгол {#-mongolian--mongolian}

**Нэрийн үг-ийн хүч чадал, entropy, хэвшмэл pattern-ийг шалгах** болон **аюулгүй hashing (боловсролын demo)-г үзүүлэх** cybersecurity төслөө.

##  Онцлог шинж

### Үндсэн функцууд
- **Бодит цагийн шинжилгээ** - Нэрийн үгийн хүч чадлын тухай шуурхай санал
- **Аюулгүй байдлын стандартын шалгалт** - Том үсэг, жижиг үсэг, цифр, тусгай тэмдэгтийг хүчинтэй болгоно
- **Entropy тооцоолол** - Нэрийн үгийн нарийн төвөгтэй байдлыг хэмжинэ
- **Хаалтын жагсаалтын шалгалт** - Нийтлэг / сул нэрийн үг илрүүлнэ
- **Аюулгүй Hashing** - SHA-256, bcrypt болон argon2 дэмжлэг

##  Хурдан эхлэл

### Суулгах
```bash
cd password_strength_checker
pip install -r requirements.txt
```

### Ажиллуулах
**Интерактив горим:** `python main.py`  
**Demo горим:** `python main.py demo`  
**Нэг нэрийн үг шалгах:** `python main.py test "MyPassword123!"`  
**Веб интерфейс:** Браузер дээрээ `web/index.html` нээнэ  
**Flask API:** `python app.py`

---

##  Threat Model & Security

### Assets Protected
- User passwords
- Password analysis results

### Threats & Mitigations
-  **Local-only analysis** - Passwords never leave browser
-  **Secure hashing** - bcrypt/argon2 for production
-  **Blacklist checking** - Detects 50+ common passwords
-  **Rate limiting** - 10 req/min prevents brute-force
-  **Constant-time comparison** - Prevents timing attacks
-  **Secure logging** - No sensitive data in logs
-  **Memory safety** - Password strings cleared after use

**Ready for cybersecurity learning and portfolio projects! 🎓**

