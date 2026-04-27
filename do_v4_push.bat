@echo off
setlocal
set GIT="C:\Program Files\Git\bin\git.exe"
cd /d C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-BLOG\cyberdudebivash-blog

echo Removing lock if present...
if exist .git\index.lock del /f .git\index.lock

echo Running git add...
%GIT% add -A > v4_result.txt 2>&1
echo ADD_EXIT:%errorlevel% >> v4_result.txt

echo Running git commit...
%GIT% commit -m "SENTINEL APEX v4.0: 9-phase engine (IOC enrichment, correlation, priority scoring, signal filter, API platform, attack chain, business impact) [skip ci]" >> v4_result.txt 2>&1
echo COMMIT_EXIT:%errorlevel% >> v4_result.txt

echo Running git push...
%GIT% push origin main >> v4_result.txt 2>&1
echo PUSH_EXIT:%errorlevel% >> v4_result.txt

echo BATCH_DONE >> v4_result.txt
echo Done. Check v4_result.txt
