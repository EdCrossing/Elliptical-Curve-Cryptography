import numpy as np
import matplotlib.pyplot as plt
script_O = "\U0001D4AA"
# this code is to create a ECDH protocol
#this exploits the DLP problem that is inherent to cyclicical groups that arise on elliptical curves in prime spaces

#Implementing EC point addition and point doubling:
#x_3 = s^2 - x_1 - x_2   mod p
#y_3 = s(x_1 - x_3) - y_1 mod p 
#both eqs hold true except s changes for addition and doubling:
#s_a = (y_2-y_1)/(x_2-x_1) mod p 
#s_d = (3x_1^2 + a)/2y_1 mod p

class EllipticCurve:
    def __init__(self, a, b, p, domain_point):
        self.a = a
        self.b = b
        self.p = p
        self.domain_point = domain_point
        self.E = f'$y^2 = x^3 + {a}x + {b}$'  

    def plot_curve(self, x_range, y_range):
        y, x = np.ogrid[y_range[0]:y_range[1]:1000j, x_range[0]:x_range[1]:1000j]
        plt.contour(x.ravel(), y.ravel(), y**2 - x**3 - self.a * x - self.b, [0], colors='blue')
        plt.axhline(0, color='black', linewidth=0.5)
        plt.axvline(0, color='black', linewidth=0.5)
        plt.grid(True)
        plt.title(f'Elliptic Curve: {self.E}')
        plt.xlabel('x')
        plt.ylabel('y')
        plt.show()

    def plot_curve_mod(self):
        p = self.p
        points = []
        for x in range(p+1):
            for y in range(p+1):
                if (y * y) % p == (x * x * x + self.a * x + self.b) % p:
                    points.append((x, y))

        if not points:
            print(f"No points found on the Elliptic curve: {self.E} mod{self.p}.")
            return

        x_vals, y_vals = zip(*points)
        plt.scatter(x_vals, y_vals, color='blue', marker=".")
        plt.axhline(0, color='black', linewidth=0.5)
        plt.axvline(0, color='black', linewidth=0.5)
        plt.grid(True)
        plt.title(f'Discrete points that fulfill {self.E} mod({p})')
        plt.xlabel('x')
        plt.ylabel('y')
        plt.xlim(-1, p)
        plt.ylim(-1, p)
        plt.gca().set_aspect('equal', adjustable='box')
        plt.show()

    def s_a(self, coords_1, coords_2):
        x1, y1 = coords_1
        x2, y2 = coords_2
        numerator = y2 - y1
        denominator = x2 - x1
        
        try:
            denominator_inv = pow(denominator, -1, self.p)
        except ValueError:
            raise ValueError(f"{script_O} addition failed")
        
        s = (numerator * denominator_inv) % self.p
        return s
    
    def s_d(self, coords):
        x1, y1 = coords
        numerator = (3 * x1**2 + self.a) % self.p
        denominator = (2 * y1) % self.p
        
        try:
            denominator_inv = pow(denominator, -1, self.p)
        except ValueError:
            raise ValueError(f"{script_O} doubling failed")
        
        s = (numerator * denominator_inv) % self.p
        return s
    
    def point_add(self, coords_1, coords_2):
        #this needs to be replaced with the binary part
        if coords_1 == coords_2:
            s = self.s_d(coords_1)
        else:
            s = self.s_a(coords_1, self.domain_point)
        
        x1, y1 = coords_1
        x2, y2 = self.domain_point
        
        x3 = (s**2 - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        
        coords_3 = (x3, y3)
        return coords_3
    
    #this manually adds up to n not using the algo in the textbook, start from coords_1 = Primitive element 
    #will define it as dP but can still be used to hop from custom points
    #coords_1 should be set to 
    def iterate_points_manual(self, coords_1):
        #just setting it big rather than using Hasse's theorem
        #hash_E_est = round(self.p + 1 + 2*np.sqrt(self.p))
        hash_E_est = 2**128
        manual_coords_3 = []
        hash_E = []
        manual_coords_3.append(coords_1)
        print(f"P: {manual_coords_3}")
        for i in range(hash_E_est):
            try:
                new_coords = self.point_add(coords_1, self.domain_point)
                print(f"{i+2}P: {new_coords}")
                manual_coords_3.append(new_coords)
                coords_1 = new_coords
            except ValueError as e:
                print(f"Iteration {i + 2}: {str(e)}")
                hash_E.append(i+2)
                break
        return manual_coords_3, hash_E

    def plot_iterated_points(self, points, hash_E):

            x_vals, y_vals = zip(*points)
            plt.scatter(x_vals, y_vals, color='blue', marker=".")
            plt.axhline(0, color='black', linewidth=0.5)
            plt.axvline(0, color='black', linewidth=0.5)
            plt.grid(True)
            plt.title(f'Plotting dP: {hash_E}{self.domain_point} over {self.E} mod({self.p})')
            plt.xlabel('x')
            plt.ylabel('y')
            plt.xlim(-1, self.p)
            plt.ylim(-1, self.p)
            plt.gca().set_aspect('equal', adjustable='box')
            plt.show()

#Variables
#elliptical curves defined by y^2 = x^3 +ax + b modp


#For the NIST P256 curve, we have a finite field defined by the prime number of 
p=2**256 - 2**224 + 2**192+2**96 - 1
a=-3
b=41058363725152142129326129780047268409114441015993725554835256314039467401291
domain_point = (48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)

##This is the curve used in Understanding Cryptography Christof Paar
#domain_point = (5,1)
#a = 2  
#b = 2
#p = 17  

curve = EllipticCurve(a, b, p, domain_point)

#for visualising the current curve
#curve.plot_curve(x_range = (-10, 10), y_range = (-10, 10))
#curve.plot_curve_mod()

#this is manual iteration with just addition, keep coords to domain point to start from beginning
#set d to a big number to catch them all, could definitely set it to the upper bound of Hasse's Theorem for smaller prime spaces
manual_iteration_coords, hash_E = curve.iterate_points_manual(coords_1 = domain_point)  
#curve.plot_iterated_points(points=manual_iteration_coords, hash_E = hash_E)
# Made a good staging area where we can look at curves
# look at the number of steps through this - not feasible when we use large numbers
# next will be to select and begin our encryption, New class!
