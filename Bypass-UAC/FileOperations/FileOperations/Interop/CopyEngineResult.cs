// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CopyEngineResult.cs" company="public domain">
// Based upon MSDN public domain software by Stephen Toub
// </copyright>
// <summary>
// The copy engine result codes.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace FileOperation
{
    /// <summary>
    /// The copy engine result.
    /// </summary>
    public enum CopyEngineResult : uint
    {
        /// <summary>
        /// The success copy
        /// </summary>
        OK = 0x0, 

        /// <summary>
        /// The success yes.
        /// </summary>
        SuccessYes = 0x00270001, 

        /// <summary>
        /// The success not handled.
        /// </summary>
        SuccessNotHandled = 0x00270003, 

        /// <summary>
        /// The success user retry.
        /// </summary>
        SuccessUserRetry = 0x00270004, 

        /// <summary>
        /// The success user ignored.
        /// </summary>
        SuccessUserIgnored = 0x00270005, 

        /// <summary>
        /// The success merge.
        /// </summary>
        SuccessMerge = 0x00270006, 

        /// <summary>
        /// The success dont process children.
        /// </summary>
        SuccessDontProcessChildren = 0x00270008, 

        /// <summary>
        /// The success already done.
        /// </summary>
        SuccessAlreadyDone = 0x0027000A, 

        /// <summary>
        /// The success pending.
        /// </summary>
        SuccessPending = 0x0027000B, 

        /// <summary>
        /// The success keep both.
        /// </summary>
        SuccessKeepBoth = 0x0027000C, 

        /// <summary>
        /// The success close program.
        /// </summary>
        SuccessCloseProgram = 0x0027000D, // Close the program using the current file

        /// <summary>
        /// The error User wants to canceled entire job
        /// </summary>
        ErrorUserCancelled = 0x80270000,

        /// <summary>
        /// The error  Engine wants to canceled entire job, don't set the CANCELLED bit
        /// </summary>
        ErrorCancelled = 0x80270001,

        /// <summary>
        /// The error Need to elevate the process to complete the operation
        /// </summary>
        ErrorRequiresElevation = 0x80270002,

        /// <summary>
        /// The error Source and destination file are the same
        /// </summary>
        ErrorSameFile = 0x80270003,

        /// <summary>
        /// The error Trying to rename a file into a different location, use move instead.
        /// </summary>
        ErrorDiffDir = 0x80270004,

        /// <summary>
        /// The error One source specified, multiple destinations
        /// </summary>
        ErrorManySrc1Dest = 0x80270005,

        /// <summary>
        /// The error The destination is a sub-tree of the source
        /// </summary>
        ErrorDestSubtree = 0x80270009,

        /// <summary>
        /// The error The destination is the same folder as the source
        /// </summary>
        ErrorDestSameTree = 0x8027000A,

        /// <summary>
        /// The error fld is file dest.
        /// </summary>
        ErrorFldIsFileDest = 0x8027000B,  // Existing destination file with same name as folder

        /// <summary>
        /// The error file is fld dest.
        /// </summary>
        ErrorFileIsFldDest = 0x8027000C,  // Existing destination folder with same name as file

        /// <summary>
        /// The error file too large.
        /// </summary>
        ErrorFileTooLarge = 0x8027000D,  // File too large for destination file system

        /// <summary>
        /// Destination device is full and happens to be removable
        /// </summary>
        ErrorRemovableFull = 0x8027000E, 

        /// <summary>
        /// The error dest is ro cd.
        /// </summary>
        ErrorDestIsRoCd = 0x8027000F,  // Destination is a Read-Only CDRom, possibly unformatted

        /// <summary>
        /// The error_ des t_ i s_ r w_ cd.
        /// </summary>
        ErrorDestIsRwCd = 0x80270010,  // Destination is a Read/Write CDRom, possibly unformatted

        /// <summary>
        /// The error Destination is a Recordable (Audio, CDRom, possibly unformatted
        /// </summary>
        ErrorDestIsRCd = 0x80270011, 

        /// <summary>
        /// The error Destination is a Read-Only DVD, possibly unformatted
        /// </summary>
        ErrorDestIsRoDvd = 0x80270012, 

        /// <summary>
        /// The error Destination is a Read/Wrote DVD, possibly unformatted
        /// </summary>
        ErrorDestIsRwDvd = 0x80270013,

        /// <summary>
        /// The error Destination is a Recordable (Audio, DVD, possibly unformatted
        /// </summary>
        ErrorDestIsRDvd = 0x80270014,

        /// <summary>
        /// The errorSource is a Read-Only CDRom, possibly unformatted
        /// </summary>
        ErrorSourceIsRoCd = 0x80270015,

        /// <summary>
        /// The error Source is a Read/Write (Audio, CDRom, possibly unformatted
        /// </summary>
        ErrorSourceIsRwCd = 0x80270016,

        /// <summary>
        /// The error Source is a Recordable (Audio, CDRom, possibly unformatted
        /// </summary>
        ErrorSourceIsRCd = 0x80270017, 

        /// <summary>
        /// The error Source is a Read-Only DVD, possibly unformatted
        /// </summary>
        ErrorSourceIsRoDvd = 0x80270018,

        /// <summary>
        /// The error Source is a Read/Wrote DVD, possibly unformatted
        /// </summary>
        ErrorSourceIsRwDvd = 0x80270019,

        /// <summary>
        /// The error Source is a Recordable (Audio, DVD, possibly unformatted.
        /// </summary>
        ErrorSourceIsRDvd = 0x8027001A, 

        /// <summary>
        /// The error Invalid source path
        /// </summary>
        ErrorInvalidFilesSrc = 0x8027001B,
        
        /// <summary>
        /// The error Invalid destination path
        /// </summary>
        ErrorInvalidFilesDest = 0x8027001C,

        /// <summary>
        /// The error Source Files within folders where the overall path is longer than MAX_PATH
        /// </summary>
        ErrorPathTooDeepSrc = 0x8027001D,
 
        /// <summary>
        /// The error Destination files would be within folders where the overall path is longer than MAX_PATH
        /// </summary>
        ErrorPathTooDeepDest = 0x8027001E,

        /// <summary>
        /// The error Source is a root directory, cannot be moved or renamed
        /// </summary>
        ErrorRootDirSrc = 0x8027001F,
 
        /// <summary>
        /// The error Destination is a root directory, cannot be renamed
        /// </summary>
        ErrorRootDirDest = 0x80270020, 

        /// <summary>
        /// The error Security problem on source
        /// </summary>
        ErrorAccessDeniedSrc = 0x80270021,

        /// <summary>
        /// The error Security problem on destination
        /// </summary>
        ErrorAccessDeniedDest = 0x80270022,
 
        /// <summary>
        /// The error Source file does not exist, or is unavailable.
        /// </summary>
        ErrorPathNotFoundSrc = 0x80270023,

        /// <summary>
        /// The error Destination file does not exist, or is unavailable
        /// </summary>
        ErrorPathNotFoundDest = 0x80270024,

        /// <summary>
        /// The error  Source file is on a disconnected network location
        /// </summary>
        ErrorNetDisconnectSrc = 0x80270025,

        /// <summary>
        /// The error Destination file is on a disconnected network location
        /// </summary>
        ErrorNetDisconnectDest = 0x80270026,

        /// <summary>
        /// The error Sharing Violation on source
        /// </summary>
        ErrorSharingViolationSrc = 0x80270027,

        /// <summary>
        /// The error  Sharing Violation on destination
        /// </summary>
        ErrorSharingViolationDest = 0x80270028,

        /// <summary>
        /// The error Destination exists, cannot replace
        /// </summary>
        ErrorAlreadyExistsNormal = 0x80270029,

        /// <summary>
        /// The error Destination with read-only attribute exists, cannot replace
        /// </summary>
        ErrorAlreadyExistsReadonly = 0x8027002A,

        /// <summary>
        /// The error Destination with system attribute exists, cannot replace
        /// </summary>
        ErrorAlreadyExistsSystem = 0x8027002B,

        /// <summary>
        /// The error Destination folder exists, cannot replace
        /// </summary>
        ErrorAlreadyExistsFolder = 0x8027002C,

        /// <summary>
        /// The error Secondary Stream information would be lost
        /// </summary>
        ErrorStreamLoss = 0x8027002D,

        /// <summary>
        /// The error  Extended Attributes would be lost.
        /// </summary>
        ErrorEaLoss = 0x8027002E,

        /// <summary>
        /// The error Property would be lost
        /// </summary>
        ErrorPropertyLoss = 0x8027002F,

        /// <summary>
        /// The error Properties would be lost
        /// </summary>
        ErrorPropertiesLoss = 0x80270030, 

        /// <summary>
        /// The error Encryption would be lost.
        /// </summary>
        ErrorEncryptionLoss = 0x80270031,

        /// <summary>
        /// Entire operation likely won't fit
        /// </summary>
        ErrorDiskFull = 0x80270032,

        /// <summary>
        /// The errorEntire operation likely won't fit, clean-up wizard available
        /// </summary>
        ErrorDiskFullClean = 0x80270033,

        /// <summary>
        /// The error Can't reach source folder
        /// </summary>
        ErrorCantReachSource = 0x80270035,

        /// <summary>
        /// The error_ recycl e_ unknow n_ error.
        /// </summary>
        ErrorRecycleUnknownError = 0x80270035,

        /// <summary>
        /// The error Recycling not available (usually turned off
        /// </summary>
        ErrorRecycleForceNuke = 0x80270036,

        /// <summary>
        /// The error Item is too large for the recycle-bin
        /// </summary>
        ErrorRecycleSizeTooBig = 0x80270037,
        
        /// <summary>
        /// The error Folder is too deep to fit in the recycle-bin
        /// </summary>
        ErrorRecyclePathTooLong = 0x80270038,

        /// <summary>
        /// The error Recycle bin could not be found or is unavailable
        /// </summary>
        ErrorRecycleBinNotFound = 0x8027003A,

        /// <summary>
        /// The error Name of the new file being created is too long
        /// </summary>
        ErrorNewfileNameTooLong = 0x8027003B,

        /// <summary>
        /// The error Name of the new folder being created is too long
        /// </summary>
        ErrorNewfolderNameTooLong = 0x8027003C,

        /// <summary>
        /// The error The directory being processed is not empty
        /// </summary>
        ErrorDirNotEmpty = 0x8027003D, 

        /// <summary>
        /// The netcach the item requested is in the negative net parsing cache
        /// </summary>
        NetcacheNegativeCache = 0x80270100,

        /// <summary>
        /// The execut for returned by command delegates to indicate that they did no work 
        /// </summary>
        ExecuteLaunchApplication = 0x80270101,

        /// <summary>
        /// The shell returned when trying to create a thumbnail extractor at too low a bitdepth for high fidelity
        /// </summary>
        ShellWrongBitdepth = 0x80270102
    }
}
