&lt;p align="center"&gt;
 &lt;a href="https://github.com/LoveProgrammingMint/Xdows-Security"&gt;
   &lt;img src=".\Xdows-Security\logo.ico" alt="Logo" width="80" height="80"&gt;
 &lt;/a&gt;

 &lt;h3 align="center"&gt;Xdows Security 4.0&lt;/h3&gt;
 &lt;p align="center"&gt;
   Check out the next-generation antivirus software built on WinUI3 + C# technology
   &lt;br /&gt;
   &lt;a href="https://xty64xty.netlify.app/zh/Xdows-Security-4.1/get-started.html"&gt;Documentation&lt;/a&gt;
   ·
   &lt;a href="https://github.com/LoveProgrammingMint/Xdows-Security/issues"&gt;Feedback&lt;/a&gt;
   ·
   &lt;a href="https://github.com/LoveProgrammingMint/Xdows-Security/releases"&gt;Download&lt;/a&gt;
   &lt;br /&gt;
   &lt;a href="README.md"&gt;English&lt;/a&gt;
   ·
   简体中文
 &lt;/p&gt;

&lt;/p&gt;

### Usage

#### Direct Use

1. Open the [Download Page](https://github.com/LoveProgrammingMint/Xdows-Security/releases) and download the latest version of `Xdows-Security.zip`
2. Extract the archive to your desired location and run `Xdows-Security.exe`

#### Build from Source

1. Environment Requirements:

   **Basic Requirements**
   1. Windows 10/11
   2. Git installed with normal access to GitHub
   
   ---
   **Building from Binary Files**
   1. Install `VS2026` or later with required workloads
   
   2. `.NET Desktop Development`, `WinUI App Development`
    
   &gt; This project requires `.NET10` framework

   ---
   **Building from Scratch**
   1. Install `VS2026` or later with required workloads
   2. Workloads: `.NET Desktop Development`, `WinUI App Development`, `Desktop Development with C++`
   3. Tips:
       This project uses `.NET10` framework and `C++20` standard
   4. Requires `Windows 11 SDK 10.0.22100` or later
   5. Install `VSCode` / `PyCharm` or other editor (using free `VSCode` as example below)
   6. Install `Python` 3.13.5+ environment (Anaconda / Miniconda recommended) 
   7. Install Python extensions
   8. Install `CUDA 13.0` or later (optional GPU acceleration, highly recommended)
   9. Install `PyTorch`
   ```sh
    pip3 install torch torchvision --index-url https://download.pytorch.org/whl/cu130 
   ```
   10. Install remaining dependencies
    
   Using repository requirements file:

   ```sh
    pip3 install -r requirements.txt
   ```

   Or using command:

   ```sh
   pip3 install numpy tqdm scikit-learn onnx thop pillow
   ```

   11. Install Vcpkg and YARA dependencies

2. Building:
   **Basic Requirements**
   1. Clone the repositories:
   ```sh
   git clone https://github.com/LoveProgrammingMint/Xdows-Security 
   git clone https://github.com/LoveProgrammingMint/SouXiaoAVEngine 
   ```
   2. Build
   
   **From Binary Files**

   Simply build the `Xdows-Security.sln` solution

   **From Scratch**

   Compile Libyara as DLL (Dynamic Link Library)

   Run `AIModel/TrainForLiuLiV5.py` to train the model
   
   For the training dataset, please contact QQ 3327867352

   Compile and assemble all solutions

### License

This project is licensed under AGPL-3.0. Please see [LICENSE](LICENSE.txt) for details.