@echo off
setlocal
set GIT="C:\Program Files\Git\bin\git.exe"
set OUT=C:\Users\Administrator\AppData\Local\Temp\v4resolve_out.txt
cd /d C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-BLOG\cyberdudebivash-blog

echo === RESOLVE + PUSH === > %OUT%

rem Accept our version of conflicted files (RSS + sitemap regenerate every 10 min anyway)
%GIT% checkout --ours rss.xml >> %OUT% 2>&1
%GIT% checkout --ours sitemap.xml >> %OUT% 2>&1
echo CHECKOUT_OURS_EXIT:%errorlevel% >> %OUT%

rem Stage resolved files
%GIT% add rss.xml sitemap.xml >> %OUT% 2>&1
echo ADD_RESOLVED_EXIT:%errorlevel% >> %OUT%

rem Also drop the stash cleanly
%GIT% stash drop >> %OUT% 2>&1

rem Commit the merge
%GIT% commit --no-edit -m "merge: resolve rss/sitemap conflicts, keep v4.0 engine state [skip ci]" >> %OUT% 2>&1
echo MERGE_COMMIT_EXIT:%errorlevel% >> %OUT%

rem Push with retry
%GIT% push origin main >> %OUT% 2>&1
echo PUSH1_EXIT:%errorlevel% >> %OUT%
if %errorlevel% EQU 0 goto DONE

%GIT% pull --rebase origin main >> %OUT% 2>&1
%GIT% push origin main >> %OUT% 2>&1
echo PUSH2_EXIT:%errorlevel% >> %OUT%

:DONE
echo COMPLETE >> %OUT%
