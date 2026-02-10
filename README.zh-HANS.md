<p align="center">
  <a href="https://github.com/LoveProgrammingMint/Xdows-Security">
    <img src=".\Xdows-Security\logo.ico" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Xdows Security 4.0</h3>
  <p align="center">
    来看看下一代基于 WinUI3 + C# 技术构建的杀毒软件
    <br />
    <a href="https://xty64xty.netlify.app/zh/Xdows-Security-4.1/get-started.html">文档</a>
    ·
    <a href="https://github.com/LoveProgrammingMint/Xdows-Security/issues">反馈</a>
    ·
    <a href="https://github.com/LoveProgrammingMint/Xdows-Security/releases">下载</a>
    <br />
    <a href="README.md">English</a>
    ·
    简体中文
  </p>

</p>


### 使用方式

#### 直接使用

1. 打开 [下载页面](https://github.com/LoveProgrammingMint/Xdows-Security/releases) 下载最新版本的 `Xdows-Security.zip`
2. 解压压缩包到目标位置，运行 `Xdows-Security.exe`

#### 编译运行

1. 环境要求：

    基本要求
    1. Windows 10/11
    2. 安装 Git 并确保能正常访问 GitHub.
    
    ---
    编译代码从`二进制文件`开始
    1. 安装 `VS2026` 或更高版本以及相关工作负载
    
    2. `.NET` 桌面开发, `WinUI 应用程序开发`
     
    > 本项目需要 `.NET10` 框架

    ---
    编译代码从 ` 0 ` 开始
    1. 安装 `VS2026` 或更高版本以及相关工作负载
    2. 工作负载: `.NET 桌面开发`, `WinUI 应用程序开发`, 使用 `C++` 的桌面开发
    3. Tips:
        本项目使用 `.NET10` 框架, `C++20` 标准
    4. 需要安装 `Windows 11 SDK 10.0.22100` 或更高版本
    5. 安装`VSCode` / `PyCharm` 或者其他编辑器 (以下以免费的`VSCode`为例)
    6. 安装`Python` 3.13.5+ 环境 (推荐使用Anaconda / Miniconda) 
    7. 安装Python插件
    8. 安装 `CUDA 13.0`或更高版本 (可选GPU加速, 十分推荐)
    9. 安装 `PyTorch`
    ```sh
     pip3 install torch torchvision --index-url https://download.pytorch.org/whl/cu130
     ```
    10. 安装其余依赖
     
     使用仓库文本
    ```sh
     pip3 install -r requirements.txt
     ```
    使用命令
    ```sh
    pip3 install numpy tqdm scikit-learn onnx thop pillow
    ```
    11. 安装Vcpkg 并安装YARA依赖

2. 编译:
    基本要求
    1. 克隆仓库
    ```sh
    git clone https://github.com/LoveProgrammingMint/Xdows-Security
    git clone https://github.com/LoveProgrammingMint/SouXiaoAVEngine
    ```
    2. 编译
    
    从`二进制文件`开始

    直接编译 `Xdows-Security.sln` 解决方案即可

      从 ` 0 `开始

    编译Libyara 为DLL(动态链接库)

    运行AIModel/TrainForLiuLiV5.py 训练模型
    
    模型训练的数据集请找QQ 3327867352获取

    编译并组装全部解决方案
    
    

### 版权说明

该项目签署了 AGPL-3.0 授权许可，详情请参阅 [LICENSE](LICENSE.txt)