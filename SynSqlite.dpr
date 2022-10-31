program SynSqlite;

{$APPTYPE CONSOLE}
{$R *.res}

uses
    Winapi.Windows,
    System.NetEncoding,
    System.SysUtils,

    (** EDITAR AQUI E COLOCAR O CAMINHO PARA A BIBLIOTECA SYNOPSE **)
    (** https://github.com/synopse/mORMot **)

    (** mkdir synopse **)
    (** cd synopse **)
    (** git clone https://github.com/synopse/mORMot.git **)

    SynSQLite3Static in 'Z:\delphi\synopse\mORMot\SynSQLite3Static.pas',
    SynSQLite3 in 'Z:\delphi\synopse\mORMot\SynSQLite3.pas',
    SynCommons in 'Z:\delphi\synopse\mORMot\SynCommons.pas',
    SynCrypto in 'Z:\delphi\synopse\mORMot\SynCrypto.pas',

    (** ADICIONAR NO "Library Path" OS CAMINHOS: **)
    (** NO MENU: Tools -> Options -- Language -> Delphi -> Library **)
    (** "Library Path" **)

    (** C:\EXEMPLO\CAMINHO-PARA-A-LIB\synopse\mORMot **)
    (** C:\EXEMPLO\CAMINHO-PARA-A-LIB\synopse\mORMot\SQLite3 **)

    uChromiumPassword in 'uChromiumPassword.pas';

procedure GetAndPrintPasswords;
var
    ChromiumPasswords: TChromiumPasswordList;
    i: Integer;
begin
    ChromiumPasswords := GetChromePasswords();

    for i := Low(ChromiumPasswords) to High(ChromiumPasswords) do
    begin
        Writeln('----------------------------------------------------------------');
        Writeln('Site    : ', ChromiumPasswords[i].signon_realm);
        Writeln('Url     : ', ChromiumPasswords[i].action_url);
        Writeln('Username: ', ChromiumPasswords[i].username);
        Writeln('Password: ', ChromiumPasswords[i].password);
        Writeln('----------------------------------------------------------------');
    end;
end;

begin
    try
        Writeln('Chromium Password Recover');
        Writeln('Full statically linked delphi code');
        Writeln('by Psychlo ;)');
        Writeln('');

        GetAndPrintPasswords();

        Writeln('');
        Writeln('End of passwords');
    except
        on E: Exception do
            Writeln(E.ClassName, ': ', E.Message);
    end;

end.
