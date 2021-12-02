


int myAtoi(char * str){
    long long res = 0;
    int sign = 0;
    while (isspace(*str))
        str++;
    if (*str == '\0')
        return 0;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        str++;
        sign = 1;
    }
    if (!isdigit(*str))
        return 0;
    while (isdigit(*str)) {
        res = res * 10 + (*str++ - '0');
        if (!sign && res > INT_MAX)
            return INT_MAX;
        else if (sign && -res < INT_MIN)
            return INT_MIN;
    }
    return sign ? -res : res;
}


int* decompressRLElist(int* nums, int numsSize, int* returnSize)
{
    int i, j;
    int *deco;
    *returnSize = 0;
    int count = 0;

    if (numsSize % 2 != 0)
        return NULL;
    for (i = 0; i < numsSize; i += 2)
        *returnSize += nums[i];

    if (!*returnSize)
        return NULL;
    deco = malloc(*returnSize * sizeof(int));
    if (!deco)
        return NULL;

    for (i = 0, j = 0; i < numsSize; i += 2) {
        if (!nums[i])
            goto out;
        for (; j < nums[i] + count; j++)
            deco[j] = nums[i + 1];
        count += nums[i];
    }
    return deco;

out:
    if (deco)
        free(deco);
    return NULL;
}
