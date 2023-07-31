#include "domain_parameters.h"
#include "point.h"
#include <gmp.h>
#include "signature.h"
#include "curves.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main(){

	int run_times = 20, total_time = 0;
    clock_t  start, stop;
    double duration;

    //Setting up domain parameters
	domain_parameters curve = domain_parameters_init();
	// domain_parameters_load_curve(curve, secp160r1);
	domain_parameters_load_curve(curve, secp224k1);
	printf("use the curve: %s\n", "secp224k1");

	//Public key
	point Q = point_init();

	//Message
	mpz_t m;mpz_init(m);

	//Private key
	mpz_t d;mpz_init(d);

	//Signature
	signature sig = signature_init();

	//Message hash just a random number
	mpz_set_str(m, "2156842181254876268462177895321953219548746516484", 10);

	gmp_randstate_t r_state;

	for(int i = 0; i < run_times; i++){
		start = clock();

		// generate key pair
		//Set private key to random integer
		gmp_randinit_default(r_state);
		mpz_urandomm(d , r_state ,curve->n);
		gmp_randclear(r_state);
		//Generate public key
		signature_generate_key(Q, d, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d KeyGen %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: KeyGen %f ms\n", total_time/run_times ); 

	total_time = 0;
	for(int i = 0; i < run_times; i++){
		start = clock();

		//Generate signature
		signature_sign(sig, m, d, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d Sign %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: Sign %f ms\n", total_time/run_times ); 

	bool result;
	//Verify result
	total_time = 0;
	for(int i = 0; i < run_times; i++){
		start = clock();

		//Generate signature
		result = signature_verify(m, sig, Q, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d Verify %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: Verify %f ms\n", total_time/run_times ); 

	domain_parameters_load_curve(curve, secp160k1);
	printf("use the curve: %s\n", "secp160k1");

	total_time = 0;
	for(int i = 0; i < run_times; i++){
		start = clock();

		// generate key pair
		//Set private key to random integer
		gmp_randinit_default(r_state);
		mpz_urandomm(d , r_state ,curve->n);
		gmp_randclear(r_state);
		//Generate public key
		signature_generate_key(Q, d, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d KeyGen %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: KeyGen %f ms\n", total_time/run_times ); 

	total_time = 0;
	for(int i = 0; i < run_times; i++){
		start = clock();

		//Generate signature
		signature_sign(sig, m, d, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d Sign %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: Sign %f ms\n", total_time/run_times ); 

	//Verify result
	total_time = 0;
	for(int i = 0; i < run_times; i++){
		start = clock();

		//Generate signature
		result = signature_verify(m, sig, Q, curve);
		//

		stop = clock(); 
		duration = ((double)(stop - start)*1000.0)/CLOCKS_PER_SEC;
		total_time += duration;
		printf( "%d Verify %f ms\n", i+1, duration );  
	}
	printf( "Average Run Time: Verify %f ms\n", total_time/run_times ); 

	//Write result to out
	if(result)
		printf("Test completed successfully.\n");
	else
		printf("Test failed!\n");

	//Release memory
	mpz_clear(m);
	mpz_clear(d);
	point_clear(Q);
	signature_clear(sig);
	domain_parameters_clear(curve);

	//Return result
	return result;
}