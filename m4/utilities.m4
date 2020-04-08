# Appends a compiler flag to a set of flags if the current compiler supports it
#
# Example:
# ADD_CFLAGS(TEST, [-Wno-unused-function])
#
# It will append -Wno-unused-function to TEST_CFLAGS if the compiler supports it
# It will not modify CFLAGS (it is saved and restored during this function)

AC_DEFUN([ADD_CFLAGS], [
    old_cflags=$CFLAGS
    CFLAGS="$CFLAGS $[$1][_CFLAGS]"
    AC_MSG_CHECKING([whether the compiler accepts $2 for [$1][_CFLAGS]])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()], [
        [$1][_CFLAGS]="$[$1][_CFLAGS] $2"
        AC_MSG_RESULT([yes])],
        [AC_MSG_RESULT([no])])
    CFLAGS="$old_cflags"
])
