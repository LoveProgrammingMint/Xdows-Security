using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Windows.Storage;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Linq;
using System.Threading.Tasks;
using IO = System.IO;

#pragma warning disable CS8601, CS8603, CS8766, CS1998, CS0114, CS8643, CS8613, CS8619, CS8767

namespace Compatibility.Windows.Storage
{
    #region ApplicationData
    public sealed class ApplicationData
    {
        public static ApplicationData Current { get; } = new ApplicationData();
        private ApplicationData() { }

        public ApplicationDataContainer LocalSettings { get; } = new ApplicationDataContainer();

        public StorageFolder LocalFolder => StorageFolder.LocalFolderInstance;
    }
    #endregion

    #region ApplicationDataContainer
    public sealed class ApplicationDataContainer
    {
        internal static readonly string StorePath = IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Xdows-Security", "LocalState", "Settings", "settings.dat");

        internal readonly Dictionary<string, JsonElement> _dict = new(StringComparer.Ordinal);

        static ApplicationDataContainer()
        {
            Directory.CreateDirectory(IO.Path.GetDirectoryName(StorePath)!);
        }

        public ApplicationDataContainer()
        {
            Values = new ApplicationDataContainerValues(this);
            Load();
        }

        public ApplicationDataContainerValues Values { get; }

        internal void Save()
        {
            try
            {
                var json = JsonSerializer.Serialize(_dict, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(StorePath, json);
            }
            catch { /* 随它去 */ }
        }

        private void Load()
        {
            if (!File.Exists(StorePath)) return;
            try
            {
                var json = File.ReadAllText(StorePath);
                var tmp = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                if (tmp != null)
                    foreach (var kv in tmp)
                        _dict[kv.Key] = kv.Value.Clone();   // 隔离引用
            }
            catch { /* 坏了就当没文件 */ }
        }
    }
    #endregion

    #region ApplicationDataContainerValues
    public sealed class ApplicationDataContainerValues : IDictionary<string, object>, IReadOnlyDictionary<string, object>
    {
        private readonly ApplicationDataContainer _owner;
        private Dictionary<string, JsonElement> Dict => _owner._dict;

        internal ApplicationDataContainerValues(ApplicationDataContainer owner)
        {
            _owner = owner;
        }

        public object? this[string key]
        {
            get => Dict.TryGetValue(key, out var v) ? ParseJsonElement(v) : null;
            set
            {
                Dict[key] = value == null
                    ? JsonSerializer.SerializeToElement(JsonValueKind.Null)
                    : JsonSerializer.SerializeToElement(value);
                _owner.Save();
            }
        }

        public ICollection<string> Keys => Dict.Keys;
        public ICollection<object> Values => Dict.Values.Select(ParseJsonElement).ToArray();
        public int Count => Dict.Count;
        public bool IsReadOnly => false;

        public void Add(string key, object? value)
        {
            Dict.Add(key, value == null
                ? JsonSerializer.SerializeToElement(JsonValueKind.Null)
                : JsonSerializer.SerializeToElement(value));
            _owner.Save();
        }

        public bool Remove(string key)
        {
            var r = Dict.Remove(key);
            if (r) _owner.Save();
            return r;
        }

        public void Clear()
        {
            Dict.Clear();
            _owner.Save();
        }

        public bool ContainsKey(string key) => Dict.ContainsKey(key);
        public bool TryGetValue(string key, out object value)
        {
            var r = Dict.TryGetValue(key, out var v);
            value = r ? ParseJsonElement(v) : new object();
            return r;
        }

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() =>
            Dict.Select(kv => new KeyValuePair<string, object?>(kv.Key, ParseJsonElement(kv.Value))).GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        #region 显式接口实现
        void ICollection<KeyValuePair<string, object?>>.Add(KeyValuePair<string, object?> item) => Add(item.Key, item.Value);
        bool ICollection<KeyValuePair<string, object?>>.Contains(KeyValuePair<string, object?> item) =>
            ((ICollection<KeyValuePair<string, JsonElement>>)Dict).Contains(new KeyValuePair<string, JsonElement>(item.Key, JsonSerializer.SerializeToElement(item.Value)));
        void ICollection<KeyValuePair<string, object?>>.CopyTo(KeyValuePair<string, object?>[] array, int arrayIndex) =>
            Dict.Select(kv => new KeyValuePair<string, object?>(kv.Key, ParseJsonElement(kv.Value)))
                .ToArray()
                .CopyTo(array, arrayIndex);
        bool ICollection<KeyValuePair<string, object?>>.Remove(KeyValuePair<string, object?> item) => Remove(item.Key);
        IEnumerable<string> IReadOnlyDictionary<string, object?>.Keys => Keys;
        IEnumerable<object?> IReadOnlyDictionary<string, object?>.Values => Values.Cast<object?>();
        #endregion

        // 关键辅助：把 JsonElement 转成合理 CLR 对象
        private static object? ParseJsonElement(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Array => element.EnumerateArray().Select(ParseJsonElement).ToList(),
                JsonValueKind.Object => element.EnumerateObject()
                                                .ToDictionary(p => p.Name, p => ParseJsonElement(p.Value)),
                _ => null
            };
        }
    }
    #endregion

    #region StorageFolder / StorageFile / 枚举 等（未改动）
    public sealed class StorageFolder
    {
        internal static readonly StorageFolder LocalFolderInstance = new StorageFolder
        {
            Path = IO.Path.GetDirectoryName(ApplicationDataContainer.StorePath)!
        };
        public string Path { get; internal set; } = null!;

        public Task<StorageFolder> CreateFolderAsync(string desiredName) =>
            Task.FromResult(CreateFolder(desiredName));
        public Task<StorageFolder> CreateFolderAsync(string desiredName, CreationCollisionOption option) =>
            Task.FromResult(CreateFolder(desiredName, option));
        public Task<StorageFile> CreateFileAsync(string desiredName) =>
            Task.FromResult(CreateFile(desiredName));
        public Task<StorageFile> CreateFileAsync(string desiredName, CreationCollisionOption option) =>
            Task.FromResult(CreateFile(desiredName, option));
        public Task<StorageFile> GetFileAsync(string name) =>
            Task.FromResult(GetFile(name));

        public StorageFolder CreateFolder(string desiredName, CreationCollisionOption option = CreationCollisionOption.FailIfExists)
        {
            var full = IO.Path.Combine(Path, desiredName);
            if (Directory.Exists(full) && option == CreationCollisionOption.FailIfExists)
                throw new IOException("Folder already exists");
            Directory.CreateDirectory(full);
            return new StorageFolder { Path = full };
        }

        public StorageFile CreateFile(string desiredName, CreationCollisionOption option = CreationCollisionOption.FailIfExists)
        {
            var full = IO.Path.Combine(Path, desiredName);
            if (File.Exists(full) && option == CreationCollisionOption.FailIfExists)
                throw new IOException("File already exists");
            Directory.CreateDirectory(IO.Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, Array.Empty<byte>());
            return new StorageFile { Path = full };
        }

        public StorageFile GetFile(string name)
        {
            var full = IO.Path.Combine(Path, name);
            if (!File.Exists(full)) throw new FileNotFoundException(full);
            return new StorageFile { Path = full };
        }
    }

    public sealed class StorageFile
    {
        public string Path { get; init; } = null!;
        public Task<StorageFile> CopyAsync(StorageFolder destinationFolder)
            => CopyAsync(destinationFolder, IO.Path.GetFileName(Path));
        public Task<StorageFile> CopyAsync(StorageFolder destinationFolder, string desiredNewName)
            => CopyAsync(destinationFolder, desiredNewName, NameCollisionOption.FailIfExists);
        public Task<StorageFile> CopyAsync(StorageFolder destinationFolder, string desiredNewName, NameCollisionOption option)
        {
            var src = Path;
            var dst = IO.Path.Combine(destinationFolder.Path, desiredNewName);
            if (IO.Path.GetFullPath(src) == IO.Path.GetFullPath(dst))
                return Task.FromResult(this);
            if (File.Exists(dst) && option == NameCollisionOption.FailIfExists)
                throw new IOException("File already exists");
            Directory.CreateDirectory(IO.Path.GetDirectoryName(dst)!);
            File.Copy(src, dst, option == NameCollisionOption.ReplaceExisting);
            return Task.FromResult(new StorageFile { Path = dst });
        }

        public static Task<StorageFile> GetFileFromApplicationUriAsync(Uri uri)
        {
            if (!uri.AbsoluteUri.StartsWith("ms-appdata:///local/"))
                throw new ArgumentException("Only ms-appdata:///local/ is supported");
            var fileName = uri.AbsoluteUri.Replace("ms-appdata:///local/", "");
            var localPath = IO.Path.Combine(
                IO.Path.GetDirectoryName(ApplicationDataContainer.StorePath)!,
                fileName);
            if (!File.Exists(localPath)) throw new FileNotFoundException(localPath);
            return Task.FromResult(new StorageFile { Path = localPath });
        }
    }

    public enum CreationCollisionOption
    {
        FailIfExists,
        ReplaceExisting,
        OpenIfExists,
        GenerateUniqueName
    }

    public enum NameCollisionOption
    {
        FailIfExists,
        ReplaceExisting,
        GenerateUniqueName
    }
    #endregion
}