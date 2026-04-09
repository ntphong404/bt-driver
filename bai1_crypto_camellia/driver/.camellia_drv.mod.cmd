savedcmd_camellia_drv.mod := printf '%s\n'   camellia_drv.o | awk '!x[$$0]++ { print("./"$$0) }' > camellia_drv.mod
