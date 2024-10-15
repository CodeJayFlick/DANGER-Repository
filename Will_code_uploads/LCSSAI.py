def lcs(X, Y, m, n, memo):
    if m == 0 or n == 0:
        return 0
    if memo[m][n] is not None:
        return memo[m][n]
    if X[m - 1] == Y[n - 1]:
        memo[m][n] = 1 + lcs(X, Y, m - 1, n - 1, memo)
    else:
        memo[m][n] = max(lcs(X, Y, m - 1, n, memo), lcs(X, Y, m, n - 1, memo))
    return memo[m][n]

def lcs_wrapper(X, Y):
    m, n = len(X), len(Y)
    memo = [[None] * (n + 1) for _ in range(m + 1)]
    return lcs(X, Y, m, n, memo)