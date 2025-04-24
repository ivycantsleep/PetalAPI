#ifndef FILE_EXTRA_H // [

#define FILE_EXTRA_H

typedef enum _FILE_INFO_BY_HANDLE_CLASS {
  FileBasicInfo,
  FileStandardInfo,
  FileNameInfo,
  FileRenameInfo,
  FileDispositionInfo,
  FileAllocationInfo,
  FileEndOfFileInfo,
  FileStreamInfo,
  FileCompressionInfo,
  FileAttributeTagInfo,
  FileIdBothDirectoryInfo,
  FileIdBothDirectoryRestartInfo,
  FileIoPriorityHintInfo,
  FileRemoteProtocolInfo,
  FileFullDirectoryInfo,
  FileFullDirectoryRestartInfo,
  FileStorageInfo,
  FileAlignmentInfo,
  FileIdInfo,
  FileIdExtdDirectoryInfo,
  FileIdExtdDirectoryRestartInfo,
  FileDispositionInfoEx,
  FileRenameInfoEx,
  FileCaseSensitiveInfo,
  FileNormalizedNameInfo,
  MaximumFileInfoByHandleClass
} FILE_INFO_BY_HANDLE_CLASS, *PFILE_INFO_BY_HANDLE_CLASS;

/* Flags for GetFinalPathNameByHandle
 */
#define FILE_NAME_NORMALIZED    0x0
#define FILE_NAME_OPENED        0x8
#define VOLUME_NAME_DOS         0x0
#define VOLUME_NAME_GUID        0x1
#define VOLUME_NAME_NT          0x2
#define VOLUME_NAME_NONE        0x4

#endif