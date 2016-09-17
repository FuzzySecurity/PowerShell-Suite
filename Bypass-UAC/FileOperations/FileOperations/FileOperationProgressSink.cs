// --------------------------------------------------------------------------------------------------------------------
// <copyright company="" file="FileOperationProgressSink.cs">
//   
// </copyright>
// <summary>
//   The file operation progress sink.
// </summary>
// 
// --------------------------------------------------------------------------------------------------------------------
namespace FileOperation
{
    using System;
    using System.Diagnostics;

    /// <summary>
    /// The file operation progress sink.
    /// </summary>
    public class FileOperationProgressSink : IFileOperationProgressSink
    {
        /// <summary>
        /// The start operations.
        /// </summary>
        public virtual void StartOperations()
        {
            TraceAction("StartOperations", string.Empty, 0);
        }

        /// <summary>
        /// The finish operations.
        /// </summary>
        /// <param name="hrResult">
        /// The hr result.
        /// </param>
        public virtual void FinishOperations(uint hrResult)
        {
            TraceAction("FinishOperations", string.Empty, hrResult);
        }

        /// <summary>
        /// The pre rename item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        public virtual void PreRenameItem(uint dwFlags, IShellItem psiItem, string pszNewName)
        {
            TraceAction("PreRenameItem", psiItem, 0);
        }

        /// <summary>
        /// The post rename item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        /// <param name="hrRename">
        /// The hr rename.
        /// </param>
        /// <param name="psiNewlyCreated">
        /// The psi newly created.
        /// </param>
        public virtual void PostRenameItem(uint dwFlags, 
            IShellItem psiItem, string pszNewName, 
            uint hrRename, IShellItem psiNewlyCreated)
        {
            TraceAction("PostRenameItem", psiNewlyCreated, hrRename);
        }

        /// <summary>
        /// The pre move item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="psiDestinationFolder">
        /// The psi destination folder.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        public virtual void PreMoveItem(
            uint dwFlags, IShellItem psiItem, 
            IShellItem psiDestinationFolder, string pszNewName)
        {
            TraceAction("PreMoveItem", psiItem, 0);
        }

        /// <summary>
        /// The post move item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="psiDestinationFolder">
        /// The psi destination folder.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        /// <param name="hrMove">
        /// The hr move.
        /// </param>
        /// <param name="psiNewlyCreated">
        /// The psi newly created.
        /// </param>
        public virtual void PostMoveItem(
            uint dwFlags, IShellItem psiItem, 
            IShellItem psiDestinationFolder, 
            string pszNewName, uint hrMove, 
            IShellItem psiNewlyCreated)
        {
            TraceAction("PostMoveItem", psiNewlyCreated, hrMove);
        }

        /// <summary>
        /// The pre copy item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="psiDestinationFolder">
        /// The psi destination folder.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        public virtual void PreCopyItem(
            uint dwFlags, IShellItem psiItem, 
            IShellItem psiDestinationFolder, string pszNewName)
        {
            TraceAction("PreCopyItem", psiItem, 0);
        }

        public virtual void PostCopyItem(uint flags, IShellItem psiItem, 
            IShellItem psiDestinationFolder, string pszNewName,
            CopyEngineResult copyResult, IShellItem psiNewlyCreated)
        {
            TraceAction("PostCopyItem", psiNewlyCreated, (uint)copyResult);
        }

        /// <summary>
        /// The pre delete item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        public virtual void PreDeleteItem(
            uint dwFlags, IShellItem psiItem)
        {
            TraceAction("PreDeleteItem", psiItem, 0);
        }

        /// <summary>
        /// The post delete item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiItem">
        /// The psi item.
        /// </param>
        /// <param name="hrDelete">
        /// The hr delete.
        /// </param>
        /// <param name="psiNewlyCreated">
        /// The psi newly created.
        /// </param>
        public virtual void PostDeleteItem(
            uint dwFlags, IShellItem psiItem, 
            uint hrDelete, IShellItem psiNewlyCreated)
        {
            TraceAction("PostDeleteItem", psiItem, hrDelete);
        }

        /// <summary>
        /// The pre new item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiDestinationFolder">
        /// The psi destination folder.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        public virtual void PreNewItem(uint dwFlags, 
            IShellItem psiDestinationFolder, string pszNewName)
        {
            TraceAction("PreNewItem", pszNewName, 0);
        }

        /// <summary>
        /// The post new item.
        /// </summary>
        /// <param name="dwFlags">
        /// The dw flags.
        /// </param>
        /// <param name="psiDestinationFolder">
        /// The psi destination folder.
        /// </param>
        /// <param name="pszNewName">
        /// The psz new name.
        /// </param>
        /// <param name="pszTemplateName">
        /// The psz template name.
        /// </param>
        /// <param name="dwFileAttributes">
        /// The dw file attributes.
        /// </param>
        /// <param name="hrNew">
        /// The hr new.
        /// </param>
        /// <param name="psiNewItem">
        /// The psi new item.
        /// </param>
        public virtual void PostNewItem(uint dwFlags, 
            IShellItem psiDestinationFolder, string pszNewName, 
            string pszTemplateName, uint dwFileAttributes, 
            uint hrNew, IShellItem psiNewItem)
        {
            TraceAction("PostNewItem", psiNewItem, hrNew);
        }

        /// <summary>
        /// The update progress.
        /// </summary>
        /// <param name="iWorkTotal">
        /// The i work total.
        /// </param>
        /// <param name="iWorkSoFar">
        /// The i work so far.
        /// </param>
        public virtual void UpdateProgress(uint iWorkTotal, uint iWorkSoFar)
        {
            Debug.WriteLine("UpdateProgress: " + iWorkSoFar + "/" + iWorkTotal);
        }

        /// <summary>
        /// The reset timer.
        /// </summary>
        public void ResetTimer()
        {
        }

        /// <summary>
        /// The pause timer.
        /// </summary>
        public void PauseTimer()
        {
        }

        /// <summary>
        /// The resume timer.
        /// </summary>
        public void ResumeTimer()
        {
        }

        /// <summary>
        /// The trace action.
        /// </summary>
        /// <param name="action">
        /// The action.
        /// </param>
        /// <param name="item">
        /// The item.
        /// </param>
        /// <param name="hresult">
        /// The hresult.
        /// </param>
        [Conditional("DEBUG")]
        private static void TraceAction(string action, string item, uint hresult)
        {
            var message = string.Format("{0} ({1})", action, (CopyEngineResult)hresult);
            if (!string.IsNullOrEmpty(item))
            {
                message += " : " + item;
            }

            Debug.WriteLine(message);
        }

        /// <summary>
        /// The trace action.
        /// </summary>
        /// <param name="action">
        /// The action.
        /// </param>
        /// <param name="item">
        /// The item.
        /// </param>
        /// <param name="hresult">
        /// The hresult.
        /// </param>
        [Conditional("DEBUG")]
        private static void TraceAction(
            string action, IShellItem item, uint hresult)
        {
            TraceAction(action, 
                item != null ? item.GetDisplayName(SIGDN.SIGDN_NORMALDISPLAY) : null, 
                hresult);
        }
    }
}
