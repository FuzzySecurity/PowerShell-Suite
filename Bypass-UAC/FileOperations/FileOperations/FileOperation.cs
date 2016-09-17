// --------------------------------------------------------------------------------------------------------------------
// <copyright company="Brown Univerity" file="FileOperation.cs">
// Public Domain
// </copyright>
// <summary>
//   The file operation.
// </summary>
// 
// --------------------------------------------------------------------------------------------------------------------
namespace FileOperation
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Runtime.InteropServices.ComTypes;
    using System.Windows.Forms;

    /// <summary>
    /// The file operation.
    /// </summary>
    public class FileOperation : IDisposable
    {
        /// <summary>
        /// The file operation.
        /// </summary>
        private readonly IFileOperation fileOperation;

        /// <summary>
        /// The callback sink.
        /// </summary>
        private readonly FileOperationProgressSink callbackSink;

        /// <summary>
        /// The sink cookie.
        /// </summary>
        private readonly uint sinkCookie;

        /// <summary>
        /// The COM GUID for file operation
        /// </summary>
        private static readonly Guid ClsidFileOperation = new Guid("3ad05575-8857-4850-9277-11b85bdb8e09");

        /// <summary>
        /// The file operation type.
        /// </summary>
        private static readonly Type FileOperationType = Type.GetTypeFromCLSID(ClsidFileOperation);

        /// <summary>
        /// The shell item guid.
        /// </summary>
        private static Guid shellItemGuid = typeof(IShellItem).GUID;

        /// <summary>
        /// The _disposed.
        /// </summary>
        private bool disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileOperation"/> class.
        /// </summary>
        public FileOperation()
            : this(null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileOperation"/> class.
        /// </summary>
        /// <param name="callbackSink">
        /// The callback sink.
        /// </param>
        public FileOperation(FileOperationProgressSink callbackSink)
            : this(callbackSink, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileOperation"/> class.
        /// </summary>
        /// <param name="callbackSink">
        /// The callback sink.
        /// </param>
        /// <param name="owner">
        /// The owner.
        /// </param>
        public FileOperation(FileOperationProgressSink callbackSink, IWin32Window owner)
        {
            this.callbackSink = callbackSink;
            this.fileOperation = (IFileOperation)Activator.CreateInstance(FileOperationType);

            this.fileOperation.SetOperationFlags(FileOperationFlags.FOF_NOCONFIRMMKDIR | FileOperationFlags.FOF_SILENT | FileOperationFlags.FOFX_SHOWELEVATIONPROMPT | FileOperationFlags.FOFX_NOCOPYHOOKS | FileOperationFlags.FOFX_REQUIREELEVATION);
            if (this.callbackSink != null)
            {
                this.sinkCookie = this.fileOperation.Advise(this.callbackSink);
            }

            if (owner != null)
            {
                this.fileOperation.SetOwnerWindow((uint)owner.Handle);
            }
        }

        /// <summary>
        /// The copy item.
        /// </summary>
        /// <param name="source">
        /// The source.
        /// </param>
        /// <param name="destination">
        /// The destination.
        /// </param>
        /// <param name="newName">
        /// The new name.
        /// </param>
        public void CopyItem(string source, string destination, string newName)
        {
            this.ThrowIfDisposed();
            using (var sourceItem = CreateShellItem(source))
            using (var destinationItem = CreateShellItem(destination))
            {
                this.fileOperation.CopyItem(sourceItem.Item, destinationItem.Item, newName, null);
            }
        }

        /// <summary>
        /// The move item.
        /// </summary>
        /// <param name="source">
        /// The source.
        /// </param>
        /// <param name="destination">
        /// The destination.
        /// </param>
        /// <param name="newName">
        /// The new name.
        /// </param>
        public void MoveItem(string source, string destination, string newName)
        {
            this.ThrowIfDisposed();
            using (var sourceItem = CreateShellItem(source))
            using (var destinationItem = CreateShellItem(destination))
            {
                this.fileOperation.MoveItem(sourceItem.Item, destinationItem.Item, newName, null);
            }
        }

        /// <summary>
        /// The rename item.
        /// </summary>
        /// <param name="source">
        /// The source.
        /// </param>
        /// <param name="newName">
        /// The new name.
        /// </param>
        public void RenameItem(string source, string newName)
        {
            this.ThrowIfDisposed();
            using (var sourceItem = CreateShellItem(source))
            {
                this.fileOperation.RenameItem(sourceItem.Item, newName, null);
            }
        }

        /// <summary>
        /// The delete item.
        /// </summary>
        /// <param name="source">
        /// The source.
        /// </param>
        public void DeleteItem(string source)
        {
            this.ThrowIfDisposed();
            using (var sourceItem = CreateShellItem(source))
            {
                this.fileOperation.DeleteItem(sourceItem.Item, null);
            }
        }

        /// <summary>
        /// News the item.
        /// </summary>
        /// <param name="folderName">Name of the folder.</param>
        /// <param name="name">The file name.</param>
        /// <param name="attrs">The file attributes.</param>
        /// <remarks></remarks>
        public void NewItem(string folderName, string name, FileAttributes attrs)
        {
            this.ThrowIfDisposed();
            using (var folderItem = CreateShellItem(folderName))
            {
                this.fileOperation.NewItem(folderItem.Item, attrs, name, string.Empty, this.callbackSink);
            }
        }

        /// <summary>
        /// The perform operations.
        /// </summary>
        public void PerformOperations()
        {
            this.ThrowIfDisposed();
            this.fileOperation.PerformOperations();
        }

        /// <summary>
        /// The dispose method
        /// </summary>
        public void Dispose()
        {
            if (this.disposed)
            {
                return;
            }

            this.disposed = true;
            if (this.callbackSink != null)
            {
                this.fileOperation.Unadvise(this.sinkCookie);
            }

            Marshal.FinalReleaseComObject(this.fileOperation);
        }

        /// <summary>
        /// The create shell item.
        /// </summary>
        /// <param name="path">
        /// The output path.
        /// </param>
        /// <returns>
        /// The Shell Item if it exists
        /// </returns>
        private static ComReleaser<IShellItem> CreateShellItem(string path)
        {
            return new ComReleaser<IShellItem>(
                (IShellItem)SHCreateItemFromParsingName(path, null, ref shellItemGuid));
        }

        /// <summary>
        /// Create shell item from name
        /// </summary>
        /// <param name="pszPath">
        /// The output path.
        /// </param>
        /// <param name="pbc">
        /// The binding context.
        /// </param>
        /// <param name="riid">
        /// The id guid .
        /// </param>
        /// <returns>
        /// The shell item.
        /// </returns>
        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        private static extern object SHCreateItemFromParsingName(
            [MarshalAs(UnmanagedType.LPWStr)] string pszPath, IBindCtx pbc, ref Guid riid);

        /// <summary>
        /// The throw if disposed.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        /// </exception>
        private void ThrowIfDisposed()
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(this.GetType().Name);
            }
        }
    }
}
