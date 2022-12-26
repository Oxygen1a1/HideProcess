# HideProcess
Hide Process
# How to hide



- 修改EPROCESS.ImageFileName
- 替换EPROCESS.FileObject.SectionObject(退出进程需要恢复,否则在删除FileObject时会蓝屏)
- PEB64

- 替换用户组

---

# Reference

[初探进程伪装](https://xz.aliyun.com/t/10435)

[修改PEB伪装进程]("https://macchiato.ink/hst/nwst/PEB/")

# Author-Oxygen

