Scientific coding project to explore the interesting maths concepts underlying elliptical curve cryptography.

Maths from the textbook: Understanding Cryptography From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms - Christof Paar, Jan Pelzl, Tim Güneysu

Further aided by Prof Paar's lectures on youtube: https://youtu.be/vnpZXJL6QCQ?si=BZ1wb8ogmNU11cR1

ECC_post_lecuters.py contains the ECC class that allows you to create, visualise and explore elliptical curves in modulo spaces. ECC_test.py tests and verifies the maths

ECC_AES.py then uses the ECC class with openSSH integration for the AES/cipher/ciphertext production.

