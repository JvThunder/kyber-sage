from sage.all import Matrix, vector, identity_matrix, zero_matrix, ZZ

def primal_attack(A, b):
    # Defining the matrix w for LLL reduction
    A_transpose = A.transpose()
    A_prime = A_transpose.rref().transpose()
    
    zero_row = Matrix(Zq, 1, n, [0, 0, 0])
    
    w = A_prime.stack(zero_row)
    w = w.augment(vector(Zq, list(b)+[1]))
    
    ll = q * identity_matrix(m - n)
    lu = zero_matrix(n, m - n)
    l = lu.stack(ll).stack(zero_matrix(1, m-n))
    
    w = w.change_ring(ZZ)
    w = w.augment(l)
    
    w_transpose = w.transpose()
    w_transpose.LLL()
    
    # Perform LLL reduction and solve for s and e
    e = w_transpose.LLL()[0][:-1]
    s_pred = A.solve_right(b - e)
    return s_pred, e


