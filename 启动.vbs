Option Explicit
' NeepuFlow 通用启动器（不弹黑框，不依赖任何人的绝对路径）
' 双击即可运行；也可以带参数，例如：  wscript 启动.vbs --selftest

Dim sh, fso, base, script, exe, args, i, o, cand, cmd
Dim roots, root, d, subName, ver, bestPath, bestVer

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
cmd = sh.ExpandEnvironmentStrings("%ComSpec%")

' ---- 1) 先从 PATH 里找 pythonw.exe ----
On Error Resume Next
Set o = sh.Exec(cmd & " /c where pythonw.exe 2>nul")
If Err.Number = 0 Then
  Do While Not o.StdOut.AtEndOfStream
    cand = Trim(o.StdOut.ReadLine())
    If Len(cand) > 0 And fso.FileExists(cand) Then
      If InStr(LCase(cand), "windowsapps") = 0 Then
        exe = cand
        Exit Do
      End If
    End If
  Loop
End If
Err.Clear
On Error GoTo 0

' ---- 2) 扫常见安装目录，挑版本号最大的 ----
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
                bestVer  = CLng(ver)
                bestPath = d.Path & "\pythonw.exe"
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
        exe = cand
        Exit Do
      End If
    Loop
  End If
  Err.Clear
  On Error GoTo 0
End If

If exe = "" Then
  MsgBox "没找到 Python。" & vbCrLf & vbCrLf & _
         "请先到 python.org 装 Python 3（安装时勾选 Add python.exe to PATH），再双击本文件。", _
         16, "NeepuFlow"
  WScript.Quit 2
End If

sh.CurrentDirectory = base
sh.Run """" & exe & """ """ & script & """" & args, 0, False
