@echo off
setlocal
set GIT="C:\Program Files\Git\bin\git.exe"
set OUT=C:\Users\Administrator\AppData\Local\Temp\v4push_out.txt
cd /d C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-BLOG\cyberdudebivash-blog

echo === v4 PUSH FINAL === > %OUT%
date /t >> %OUT%

rem Clean any stash
%GIT% stash list >> %OUT% 2>&1

rem Pop stash if any
%GIT% stash pop >> %OUT% 2>&1
echo STASH_POP_EXIT:%errorlevel% >> %OUT%

rem Add everything
%GIT% add -A >> %OUT% 2>&1
echo ADD_EXIT:%errorlevel% >> %OUT%

rem Commit new files
%GIT% commit -m "chore: add pipeline result files + v4 push scripts [skip ci]" >> %OUT% 2>&1
echo COMMIT_EXIT:%errorlevel% >> %OUT%

rem Fetch remote
%GIT% fetch origin main >> %OUT% 2>&1
echo FETCH_EXIT:%errorlevel% >> %OUT%

rem Merge remote into local
%GIT% merge --no-edit origin/main >> %OUT% 2>&1
echo MERGE_EXIT:%errorlevel% >> %OUT%

rem Push
%GIT% push origin main >> %OUT% 2>&1
echo PUSH_EXIT:%errorlevel% >> %OUT%

echo COMPLETE >> %OUT%
