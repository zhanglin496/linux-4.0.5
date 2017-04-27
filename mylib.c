
//判断依旧都是利用在ascii码表中 0~9 A~F a~f
//对应的值是连续递增的，
#define isxdigit(x) (isupper(x) || islower(x))
#define isdigit(x)	((x) >= '0' && (x) <= '9')
#define islower(x) ((x) >= 'a') && (x) <= 'f')
#define isupper(x) ((x) >= 'A') && (x) <= 'F')
//A~F 和a~f 之间的差值是固定
#define toupper(x) (islower(x) ? (x) - ('a' - 'A') : (x))
#define tolower(x) (isupper(x) ? (x) + ('a' - 'A') : (x))



