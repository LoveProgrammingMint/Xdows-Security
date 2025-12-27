<p align="center">
  <a href="https://github.com/XTY64XTY12345/Xdows-Security-4">
    <img src="..\Xdows-Security\logo.ico" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Xdows Security 4.0</h3>
  <p align="center">
    来看看下一代基于 WinUI3 + C# 技术构建的杀毒软件
    <br />
    <a href="https://xty64xty.netlify.app/zh/Xdows-Security-4.1/get-started.html">文档</a>
    ·
    <a href="https://github.com/XTY64XTY12345/Xdows-Security/issues">反馈</a>
    ·
    <a href="https://github.com/XTY64XTY12345/Xdows-Security/releases">下载</a>
    <br />
    简体中文
  </p>

</p>

# IceZero Studio Plugin Framework
## Chinese - 中文
## IceZero Studio 插件框架允许开发者为 Xdows Security 创建功能丰富的插件

格式：
- 插件以 `.NET10` `WinUI3` `类库（DLL）`的形式存在
- 插件`必须`使用 IceZero Studio 提供的 Plugin 框架 以保证兼容性

插件项目打包后格式：
- Information.json ：包含插件的元数据文件（json 格式）
- 插件 DLL 文件 (默认指向Plugin.dll): 包含插件的主要功能代码 (.NET WinUI3 类库)
- 其他资源文件（可选）：如图标、配置文件等*
- README.md（可选）：插件的使用说明和文档*
- LICENSE（可选）：插件的许可证信息*

*可选文件根据插件的具体需求决定是否包含，但 Information.json 和插件 DLL 文件是必须的。

## 插件开发指南
### 环境准备
1. 安装 Visual Studio 2026 或更高版本，确保安装了 .NET10 框架和 WinUI3 工作负载。
2. 下载并安装 IceZero Studio 提供的 Plugin 框架。
### 创建插件项目
3. 创建一个新的 .NET10 WinUI3 类库项目(或者重写框架)。
4. 符合 IceZero Studio 提供的 Plugin 框架所有接口。
### 实现插件的生命周期方法
1. 在Load~Init函数中完成初始化工作。
1. 在Entry函数中初始化插件页面&装载功能（ViewModel/Model）并返回页面对象。
1. 在Unload~Exit函数中完成插件卸载工作。
### 打包和发布插件
1. 编译项目，生成 DLL 文件。
1. 创建 Information.json 文件，填写插件的元数据。
1. 将 DLL 文件和 Information.json 文件打包成插件文件夹。
1. 将插件文件夹放置在 Xdows Security 的插件目录中。或 给与IceZero Studio/Xdows 官方 审核发布`特定格式安装包`。

##### 可以使用 IceZero Studio 提供的打包工具来`简化`此过程。
- 格式：
```bash
PkgTool --input [DLL] --info [INFO] --output [OUTPUT DIR]
```
- 示例：
```bash
PkgTool --input ./MyPluginProject/bin/Release/net10-windows/MyPlugin.dll --info ./Information.json --output ./MyPluginPackage
```
