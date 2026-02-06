using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using System;
using System.Buffers;
using System.IO;
using System.Linq;

namespace Self_Heuristic
{

    public class LiuLiV5Classifier(string modelPath) : IDisposable
    {
        private readonly InferenceSession _session = new(modelPath);
        private readonly DenseTensor<float> _inputTensor = new([1, 3, 64, 64]);
        private const int INPUT_SIZE = 3 * 64 * 64;
        public bool Predict(string imagePath)
        {
            var bytePool = ArrayPool<byte>.Shared;
            byte[] byteBuffer = bytePool.Rent(INPUT_SIZE);

            try
            {
                // 读取文件并补全
                using var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, FileOptions.SequentialScan);
                int bytesRead = fs.Read(byteBuffer, 0, INPUT_SIZE);

                // 补全不足的部分
                for (int i = bytesRead; i < INPUT_SIZE; i++)
                    byteBuffer[i] = 0;

                // 归一化并直接填充到Tensor的Buffer中
                var tensorSpan = _inputTensor.Buffer.Span;
                for (int i = 0; i < INPUT_SIZE; i++)
                    tensorSpan[i] = byteBuffer[i] / 255.0f;

                // 执行推理
                var inputs = new[]
                {
            NamedOnnxValue.CreateFromTensor(_session.InputNames[0], _inputTensor)
        };

                using var results = _session.Run(inputs);
                var output = results[0].AsTensor<float>();

                // Softmax计算
                var logits = (Span<float>)[output[0, 0], output[0, 1]];
                var max = MathF.Max(logits[0], logits[1]);

                logits[0] = MathF.Exp(logits[0] - max);
                logits[1] = MathF.Exp(logits[1] - max);

                var sum = logits[0] + logits[1];
                logits[0] /= sum;
                logits[1] /= sum;

                return logits[0] < 0.25f;
            }
            finally
            {
                bytePool.Return(byteBuffer, false);
            }
        }
        public void Dispose()
        {
            _session?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}