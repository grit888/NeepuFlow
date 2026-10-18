Option Explicit
' NeepuFlow 通用启动器（不弹黑框，不依赖任何人的绝对路径）
' 双击即可运行；也可以带参数，例如：  wscript 启动.vbs --selftest
'
' 注意：光"找到 pythonw.exe"并不够 —— 有些 Python（微软商店版、精简版、
' 工具自带的嵌入式版）根本没装 tkinter，用它起来会立刻报错退出，
' 而 pythonw 没有控制台，用户看到的就是"双击毫无反应"。
' 所以每个候选都要先用 import tkinter 试一次，通过才敢用。

Dim sh, fso, base, script, exe, args, i, o, cand, cmd
Dim roots, root, d, subName, ver, bestPath, bestVer, firstCand

Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

base   = fso.GetParentFolderName(WScript.ScriptFullName)
script = base & "\neepu_flow.py"

If Not fso.FileExists(script) Then
  ' 兼容：程序在 NeepuFlow\ 子目录里
  If fso.FileExists(base & "\NeepuFlow\neepu_flow.py") Then
    base   = base & "\NeepuFlow"
    script = base & "\neepu_flow.py"
  Else
    MsgBox "找不到 neepu_flow.py。" & vbCrLf & vbCrLf & _
           "请把本文件放在和它同一个文件夹里。", 16, "NeepuFlow"
    WScript.Quit 1
  End If
End If

' ---- 透传参数 ----
args = ""
For i = 0 To WScript.Arguments.Count - 1
  args = args & " """ & WScript.Arguments(i) & """"
Next

exe = ""
firstCand = ""
cmd = sh.ExpandEnvironmentStrings("%ComSpec%")

' ---- 1) 先从 PATH 里找 pythonw.exe（要真有 tkinter 才算数）----
On Error Resume Next
Set o = sh.Exec(cmd & " /c where pythonw.exe 2>nul")
If Err.Number = 0 Then
  Do While Not o.StdOut.AtEndOfStream
    cand = Trim(o.StdOut.ReadLine())
    If Len(cand) > 0 And fso.FileExists(cand) Then
      If InStr(LCase(cand), "windowsapps") = 0 Then
        If firstCand = "" Then firstCand = cand
        If HasTk(cand) Then
          exe = cand
          Exit Do
        End If
      End If
    End If
  Loop
End If
Err.Clear
On Error GoTo 0

' ---- 2) 扫常见安装目录，挑版本号最大、而且带 tkinter 的 ----
If exe = "" Then
  bestPath = ""
  bestVer  = -1
  roots = Array(sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python", _
                sh.ExpandEnvironmentStrings("%ProgramFiles%") & "\Python", _
                sh.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & "\Python", _
                sh.ExpandEnvironmentStrings("%SystemDrive%") & "\")
  For Each root In roots
    If fso.FolderExists(root) Then
      For Each d In fso.GetFolder(root).SubFolders
        subName = LCase(d.Name)
        If Left(subName, 6) = "python" Then
          ver = ""
          For i = 1 To Len(subName)
            If Mid(subName, i, 1) >= "0" And Mid(subName, i, 1) <= "9" Then ver = ver & Mid(subName, i, 1)
          Next
          If ver <> "" Then
            If CLng(ver) > bestVer Then
              If fso.FileExists(d.Path & "\pythonw.exe") Then
                If HasTk(d.Path & "\pythonw.exe") Then
                  bestVer  = CLng(ver)
                  bestPath = d.Path & "\pythonw.exe"
                End If
              End If
            End If
          End If
        End If
      Next
    End If
  Next
  exe = bestPath
End If

' ---- 3) 最后试 py 启动器带的 pyw.exe ----
If exe = "" Then
  On Error Resume Next
  Set o = sh.Exec(cmd & " /c where pyw.exe 2>nul")
  If Err.Number = 0 Then
    Do While Not o.StdOut.AtEndOfStream
      cand = Trim(o.StdOut.ReadLine())
      If Len(cand) > 0 And fso.FileExists(cand) Then
        If HasTk(cand) Then
          exe = cand
          Exit Do
        End If
      End If
    Loop
  End If
  Err.Clear
  On Error GoTo 0
End If

If exe = "" Then
  If firstCand <> "" Then
    MsgBox "找到 Python 了，但它没带图形界面库（tkinter），程序起不来。" & vbCrLf & vbCrLf & _
           "找到的是：" & vbCrLf & firstCand & vbCrLf & vbCrLf & _
           "解决办法：到 python.org 重新装一次 Python 3，" & vbCrLf & _
           "安装时把「tcl/tk and IDLE」也勾上（默认就勾着），再双击本文件。", 16, "NeepuFlow"
  Else
    MsgBox "没找到 Python。" & vbCrLf & vbCrLf & _
           "请先到 python.org 装 Python 3（安装时勾选 Add python.exe to PATH），再双击本文件。", _
           16, "NeepuFlow"
  End If
  WScript.Quit 2
End If

sh.CurrentDirectory = base
sh.Run """" & exe & """ """ & script & """" & args, 0, False


' ---- 判断某个 pythonw/pyw 有没有 tkinter：用同目录的 python.exe / py.exe 试 import ----
Function HasTk(p)
  Dim py, rc
  HasTk = True                        ' 没法验证就当能用，别把好的挡掉
  py = p
  If LCase(Right(py, 10)) = "pythonw.exe" Then
    py = Left(py, Len(py) - 10) & "python.exe"
  ElseIf LCase(Right(py, 6)) = "pyw.exe" Then
    py = Left(py, Len(py) - 6) & "py.exe"
  End If
  If Not fso.FileExists(py) Then Exit Function
  On Error Resume Next
  rc = sh.Run("""" & py & """ -c ""import tkinter""", 0, True)
  If Err.Number <> 0 Then
    rc = 0
    Err.Clear
  End If
  On Error GoTo 0
  HasTk = (rc = 0)
End Function
