command:	gcc -o ecdsa ecdsa.c curves.c domain_parameters.c point.c signature.c numbertheory.c random.c -lm -lgmp
execute:	./ecdsa