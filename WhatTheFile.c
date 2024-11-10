#include <Windows.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "../lib/win.h"

_universal uni;
_path path;
HANDLE console;
HANDLE file;
WORD saved_attrib;
CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
DWORD attrib;
BY_HANDLE_FILE_INFORMATION info;
FILE_STANDARD_INFO std;
PFILE_STREAM_INFO stream;
FILE_COMPRESSION_INFO compress;
FILE_RENAME_INFO rname;
FILE_STORAGE_INFO storage;
FILE_REMOTE_PROTOCOL_INFO remote;
SHFILEINFOA shellinfo;

BOOL
DisplayStreamInfo(HANDLE hFile)
{

    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE STREAM INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");

    PFILE_STREAM_INFO currentStreamInfo;
    BOOL result;
    PFILE_STREAM_INFO streamInfo;
    ULONG streamInfoSize;


    //
    // Allocate an information structure that is hopefully large enough to
    // retrieve stream information.
    //

    streamInfoSize = sizeof(FILE_STREAM_INFO) + (sizeof(WCHAR) * MAX_PATH);

retry:

    streamInfo = (PFILE_STREAM_INFO) LocalAlloc(LMEM_ZEROINIT,
                                                    streamInfoSize);


    if (streamInfo == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }

    result = GetFileInformationByHandleEx( hFile,
                                               FileStreamInfo,
                                               streamInfo,
                                               streamInfoSize );

    if (!result) {
        //
        // If our buffer wasn't large enough try again with a larger one.
        //
        if (GetLastError() == ERROR_MORE_DATA) {
            streamInfoSize *= 2;
            goto retry;
        }
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("  Failure fetching stream information: 0x%09X\n", GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
        LocalFree(streamInfo);
        return result;
    }
    currentStreamInfo = streamInfo;
    do {
        printf("  Stream Name: %S\n", currentStreamInfo->StreamName);
        printf("    Stream Size: %d\n", currentStreamInfo->StreamSize.LowPart);
        printf("    Stream Allocation Size: %d\n", currentStreamInfo->StreamAllocationSize.LowPart);

        if (currentStreamInfo->NextEntryOffset == 0) {
            currentStreamInfo = NULL;
        } else {
            currentStreamInfo = 
                (PFILE_STREAM_INFO) ((PUCHAR)currentStreamInfo +
                                     currentStreamInfo->NextEntryOffset);
        }
    } while (currentStreamInfo != NULL);


    LocalFree(streamInfo);
    return true;
}

int PrintFileAttributes(ULONG FileAttributes)
{
    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE ATTRIBUTES ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");


    if (FileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
        printf("  Archive\n");
        FileAttributes &= ~FILE_ATTRIBUTE_ARCHIVE;
    }
    if (FileAttributes & FILE_ATTRIBUTE_READONLY) {
        printf("  Read-Only\n");
        FileAttributes &= ~FILE_ATTRIBUTE_READONLY;
    }
    if (FileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        printf("  Hidden\n");
        FileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
    }
    if (FileAttributes & FILE_ATTRIBUTE_SYSTEM) {
        printf("  System\n");
        FileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
    }
    if (FileAttributes & FILE_ATTRIBUTE_NORMAL) {
        printf("  Normal\n");
        FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
    }
    if (FileAttributes & FILE_ATTRIBUTE_TEMPORARY) {
        printf("  Temporary\n");
        FileAttributes &= ~FILE_ATTRIBUTE_TEMPORARY;
    }
    if (FileAttributes & FILE_ATTRIBUTE_COMPRESSED) {
        printf("  Compressed\n");
        FileAttributes &= ~FILE_ATTRIBUTE_COMPRESSED;
    }
    return 0;
}

int showbasic(const char *argv,HANDLE file)
{
    SHGetFileInfoA(argv,FILE_ATTRIBUTE_NORMAL,&shellinfo,sizeof(shellinfo),SHGFI_TYPENAME | SHGFI_DISPLAYNAME);
    GetFileInformationByHandleEx(file,FileStandardInfo,&std,sizeof(std));

    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE BASIC INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");

    printf("  File name: ");
    if(shellinfo.szDisplayName == NULL){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value: shellinfo.szDisplayName: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n", shellinfo.szDisplayName);
    }
    printf("  File type: ");
    if(shellinfo.szDisplayName == NULL){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("failed to fetch value: shellinfo.szTypeName: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n", shellinfo.szTypeName);
    }
    
    printf("  Allocation size: ");
    printf("%lu\n",std.AllocationSize.LowPart);
    printf("  End of file: ");
    printf("%lu\n",std.EndOfFile.LowPart);
    printf("  Number of links: ");
    printf("%lu\n", std.NumberOfLinks);

    printf("  Executable: ");
    DWORD type;
    if(GetBinaryTypeA(argv,&type)){
        SetConsoleTextAttribute(console,RGB(6,1,10));
        printf("yes ");
        SetConsoleTextAttribute(console,saved_attrib);
        //get binary type here
        switch(type){
            case SCS_64BIT_BINARY:
                printf("(64 bit)\n");
                break;

            case SCS_32BIT_BINARY:
                printf("(32 bit)\n");
                break;

            case SCS_WOW_BINARY:
                printf("(16 bit)\n");
                break;

            case SCS_DOS_BINARY:
                printf("(MS-DOS)\n");
                break;

            case SCS_POSIX_BINARY:
                printf("(POSIX)\n");
                break;

            case SCS_PIF_BINARY:
                printf("(PIF)\n");
                break;

            case SCS_OS216_BINARY:
                printf("(OS/2 16 bit)\n");
                break;

            default:
                printf("\n");
                break;
        }
    } else {
        SetConsoleTextAttribute(console,FOREGROUND_RED*2);
        printf("no\n");
        SetConsoleTextAttribute(console,saved_attrib);
    }


    printf("  Pending deletion: ");
    if(std.DeletePending){
        SetConsoleTextAttribute(console,RGB(6,1,10));
        printf("yes\n");
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        SetConsoleTextAttribute(console,FOREGROUND_RED*2);
        printf("no\n");
        SetConsoleTextAttribute(console,saved_attrib);
    }

    return 0;

}

void showpaths(const char *name)
{
    getpath(name,&path);
    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE PATHS ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");
    printf("  NT Path: ");
    if(strlen(path.NtPath) <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch path.NtPath: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n",path.NtPath);
    }
    printf("  DOS Path: ");
    if(strlen(path.DosPath) <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch path.DosPath: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n",path.DosPath);
    }
    printf("  Volume GUID path: ");
    if(strlen(path.GuidPath) <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch path.GuidPath: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n",path.GuidPath);
    }
    printf("  None path: ");
    if(strlen(path.NonePath) <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch path.NonePath: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%s\n",path.NonePath);
    }
}

int filestorageinfo()
{
    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE STORAGE INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");
    GetFileInformationByHandleEx(file,FileStorageInfo,&storage,sizeof(storage));

    printf("  Effective Physical Bytes per sector for atomicity: ");
    if(storage.FileSystemEffectivePhysicalBytesPerSectorForAtomicity <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.FileSystemEffectivePhysicalBytesPerSectorForAtomicity: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n",storage.FileSystemEffectivePhysicalBytesPerSectorForAtomicity);
    }
    printf("  Physcial bytes per sector for atomicity: ");
    if(storage.PhysicalBytesPerSectorForAtomicity <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.PhysicalBytesPerSectorForAtomicity: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n", storage.PhysicalBytesPerSectorForAtomicity);
    }
    printf("  Physcial bytes per sector for performance: ");
    if(storage.PhysicalBytesPerSectorForPerformance <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.PhysicalBytesPerSectorForPerformance: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n", storage.PhysicalBytesPerSectorForPerformance);
    }
    printf("  Byte offset for partition alignment: ");
    if(storage.ByteOffsetForPartitionAlignment <= 1 && GetLastError() != ERROR_SUCCESS){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.ByteOffsetForPartitionAlignment: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n", storage.ByteOffsetForPartitionAlignment);
    }

    printf("  Byte offset for sector alignment: ");
    if(storage.ByteOffsetForSectorAlignment <= 0 && GetLastError() != ERROR_SUCCESS){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.ByteOffsetForSectorAlignment: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n", storage.ByteOffsetForSectorAlignment);
    }

    printf("  Logical bytes per sector: ");
    if(storage.LogicalBytesPerSector <= 1){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Failed to fetch value storage.LogicalBytesPerSector: 0x%09X\n",GetLastError());
        SetConsoleTextAttribute(console,saved_attrib);
    } else {
        printf("%lu\n", storage.LogicalBytesPerSector);
    }
    return 0;
}

bool basic = false;
int main(int argc, char *argv[])
{
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(console, &consoleInfo);
    saved_attrib = consoleInfo.wAttributes;
    uni.pid = GetCurrentProcessId();
    uni.hProcess = OpenProcess(FILE_ALL_ACCESS, FALSE, uni.pid);
    GetCurrentDirectoryA(256,uni.CurrentDirectory);

    SetConsoleTextAttribute(console,FOREGROUND_GREEN);
    printf("What The File (64 bit)\n");
    printf("Windows file information extraction tool.\n");
    printf("Created using the C programming language :D!\n");
    SetConsoleTextAttribute(console,saved_attrib);
    SetConsoleTextAttribute(console,FOREGROUND_GREEN | FOREGROUND_INTENSITY | FOREGROUND_INTENSITY);
    printf("=====================================================");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");
    if(argv[1] == NULL){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Expected a file for argument 2, got NULL.");
        SetConsoleTextAttribute(console,saved_attrib);
        return 1;
    }
    if(argv[2] != NULL){
        if(strcmpi(argv[2],"/basic") == 0){
            basic = true;
        }
    }
    file = CreateFile(argv[1],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL);
    if(file == INVALID_HANDLE_VALUE){
        if(GetLastError() == ERROR_FILE_NOT_FOUND){
            SetConsoleTextAttribute(console,FOREGROUND_RED);
            printf("The specified file: '%s' does not exist.",argv[1]);
            SetConsoleTextAttribute(console,saved_attrib);
            return 1;
        }
    }
    attrib = GetFileAttributesA(argv[1]);
    if(attrib &FILE_ATTRIBUTE_DIRECTORY){
        SetConsoleTextAttribute(console,FOREGROUND_RED);
        printf("Expected a file, got a directory: '%s'",argv[1]);
        SetConsoleTextAttribute(console,saved_attrib);
        return 1;
    }
    
    //get data
    SHGetFileInfoA(argv[1],FILE_ATTRIBUTE_NORMAL,&shellinfo,sizeof(shellinfo),SHGFI_TYPENAME | SHGFI_DISPLAYNAME);
    GetFileInformationByHandle(file,&info);
    GetFileInformationByHandleEx(file,FileStandardInfo,&std,sizeof(std));
    GetFileInformationByHandleEx(file,FileRenameInfoEx,&rname,sizeof(rname) == 0);

    showbasic(argv[1],file);

    if(basic == true){
        return 0;
    }

    showpaths(argv[1]);

    PrintFileAttributes(attrib);

    DisplayStreamInfo(file);

    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE COMPRESSION INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");
    GetFileInformationByHandleEx(file,FileCompressionInfo,&compress,sizeof(compress));
    printf("  Compressed file size: %d\n",compress.CompressedFileSize.LowPart);
    printf("  Compression format: %d\n",compress.CompressionFormat);
    printf("  Chunck shift: %u\n",compress.ChunkShift);
    printf("  Cluster shift: %u\n",compress.ClusterShift);
    printf("  Compression unit shift: %u\n",compress.CompressionUnitShift);

    filestorageinfo();

    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE REMOTE PROTOCOL INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n\n");
    GetFileInformationByHandleEx(file,FileRemoteProtocolInfo,&remote,sizeof(remote));
    printf("  Protocol: %lu\n",remote.Protocol);
    printf("  Protocol major version: %lu\n",remote.ProtocolMajorVersion);
    printf("  Protocol minor version: %lu\n",remote.ProtocolMinorVersion);
    printf("  Protocol revision: %lu\n", remote.ProtocolRevision);
    printf("  SMB2 Share flags: %lu\n",remote.ProtocolSpecific.Smb2.Share.ShareFlags);
    printf("  SMB2 Share Capabilities: %lu\n", remote.ProtocolSpecific.Smb2.Server.Capabilities);
    printf("  SMB2 Server Capabilities: %lu\n",remote.ProtocolSpecific.Smb2.Server.Capabilities);
    printf("\n");
    SetConsoleTextAttribute(console,FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[ FILE EXTENDED INFORMATION ]");
    SetConsoleTextAttribute(console,saved_attrib);
    printf("\n");
    FILE_CASE_SENSITIVE_INFO csinfo;
    FILE_END_OF_FILE_INFO end;
    FILE_ID_INFO id;
    FILE_IO_PRIORITY_HINT_INFO io;
    FILE_DISPOSITION_INFO_EX disp;
    GetFileInformationByHandleEx(file,FileDispositionInfoEx,&disp,sizeof(disp));
    GetFileInformationByHandleEx(file,FileEndOfFileInfo,&end,sizeof(end));
    GetFileInformationByHandleEx(file,FileCaseSensitiveInfo,&csinfo,sizeof(csinfo));
    GetFileInformationByHandleEx(file,FileIdInfo,&id,sizeof(id));
    GetFileInformationByHandleEx(file,FileIoPriorityHintInfo,&io,sizeof(io));
    printf("  Case sensitive information flags: %d\n",csinfo.Flags);
    printf("  End of file: %lu\n", end.EndOfFile.LowPart);
    printf("  File ID: %d\n",*id.FileId.Identifier);
    printf("  Volume serial number: %llu\n",id.VolumeSerialNumber);
    printf("  File disposition info flags: %lu\n",disp.Flags);
    printf("  IO Priority hint: %lu\n", io.PriorityHint);


    CloseHandle(file);
    return 0;
}