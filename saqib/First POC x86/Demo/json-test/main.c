/*
 * main.c
 *
 *  Created on: Apr 19, 2018
 *      Author: root
 */


/*
 * A simple example of json string parsing with json-c.
 *
 * clang -Wall -g -I/usr/include/json-c/ -o json_parser json_parser.c -ljson-c
 */
#include <json.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <gmodule.h>

/***********************************Date Structures************************************************************/
typedef struct _argument{
	int argument_number;
	char value[256];
}targument,*argument;
typedef struct _API{
	char api_name[256];
	int argument_count;
	GSList* argument_list;
}api,*Papi;
typedef struct _Event {
	char Name[256];
	GQueue *queueofapi;
	int api_count;
}Event,*PEvent;

 GSList *Eventlist = NULL;  // Final List

api *api_holder ;





static void sample(gpointer opaque, gpointer unused)
{
	api *myapi = (api*)opaque;
	char *api_name = (char*)unused ;
	printf("%s",myapi->api_name);
}


static int check_queue(gpointer opaque,  gpointer unused)
{

	//printf("Event name is: %s",event->Name);
	Event *event =(Event*) opaque;
	char *api_name = (char*)unused ;
	//printf("%s",event->Name);
	//g_queue_foreach(event->queueofapi,sample,api_name);
	if (event->api_count == 0)
	{
		return -1;
	}
	else
	{
		api *myapi = (api*)g_queue_peek_head(event->queueofapi);
			if(strcmp(api_name,myapi->api_name)==0)
					{
						event->api_count--;
						if(event->api_count == 0)
								{
									printf("Event Triggered: %s",event->Name);
									return 0;
								}
					//	printf("%d\n",event->api_count);
						g_queue_pop_head (event->queueofapi);
						return 0;
					}


	}


		//api *myapi = (api*)g_queue_peek_head(event->queueofapi);
		//printf("%s",myapi->api_name);
	//	if(strcmp(api_name,myapi->api_name)==0)
	//	{
	//		event->api_count--;
	//		if(event->api_count == 0)
	//				{
	//					printf("Event Triggered: %s",event->Name);
	//				}
		//	printf("%d\n",event->api_count);
		//	g_queue_pop_head (event->queueofapi);
	//	}

//	api *myapi = (api*)g_queue_peek_tail(event->queueofapi);
//	printf("Event name is: %s\n",myapi->api_name);


//	api *myapi2 = (api*)g_queue_peek_tail(event->queueofapi);
//	printf("Event name is: %s\n",myapi->api_name);
}


/*Test Function */

int match(void)
{
	Event *e1 ;
	e1 = malloc(sizeof(Event));
	e1->api_count = 4;
	strcpy(e1->Name,"Code Injection");

	api *api1,*api2,*api3,*api4 ;
	api1 = malloc(sizeof(api));
	api2 = malloc(sizeof(api));
	api3 = malloc(sizeof(api));
	api4 = malloc(sizeof(api));
	strcpy(api1->api_name,"Sleep");
	strcpy(api2->api_name,"CreateFile");
	strcpy(api3->api_name,"NTCreateRemoteThread");
	strcpy(api4->api_name,"ResumeThread");

	e1->queueofapi = g_queue_new ();
	g_queue_push_head(e1->queueofapi,api1);
	g_queue_push_head(e1->queueofapi,api2);
	g_queue_push_head(e1->queueofapi,api3);
	g_queue_push_head(e1->queueofapi,api4);

	Eventlist = g_slist_append(Eventlist , e1);

	Event *e2 ;
	e2 = malloc(sizeof(Event));
	e2->api_count = 4;
	strcpy(e2->Name,"Mal_file");

	api *api5,*api6,*api7,*api8 ;
	api5 = malloc(sizeof(api));
		api6 = malloc(sizeof(api));
		api7 = malloc(sizeof(api));
		api8 = malloc(sizeof(api));
	strcpy(api5->api_name,"Access_c");
	strcpy(api6->api_name,"CreateFile");
	strcpy(api7->api_name,"ABCD");
	strcpy(api8->api_name,"hello");

	e2->queueofapi = g_queue_new ();
	g_queue_push_head(e2->queueofapi,api5);
	g_queue_push_head(e2->queueofapi,api6);
	g_queue_push_head(e2->queueofapi,api7);
	g_queue_push_head(e2->queueofapi,api8);


	Eventlist = g_slist_append(Eventlist , e2);

	//g_slist_foreach(myEventlist,check_queue,NULL);



	//g_print("Hello world");


	return 0;
}

/*Check if API in any sequence*/
static void check_api_in_event_sequence(char *api_name){
	g_slist_foreach(Eventlist,check_queue,api_name);

}



void json_parse_my(json_object * jobj) ;



int event_counter=0;
int api_counter =0 ;
int argument_counter=  0 ;

Event *global_space_event;
api *global_space_api ;
targument *global_space__argument ;

void json_parse_array_my( json_object *jobj, char *key) {
	global_space_api = malloc (sizeof(api) * 2048) ;
	global_space__argument = malloc (sizeof(targument) * 2048);
	global_space_event = malloc(sizeof(Event)*2048);

	void json_parse(json_object * jobj); /*Forward Declaration*/
	enum json_type type;

	json_object *jarray = jobj; /*Simply get the array*/

	if(key) {
    jarray = json_object_object_get(jobj, key); /*Getting the array if it is a key value pair*/
	}

	int arraylen = json_object_array_length(jarray); /*Getting the length of the array*/
	printf("Array Length: %dn",arraylen);
	int i;

	json_object * jvalue;


	for (i=0; i< arraylen; i++){/*List of Events*/

		jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/

	  	json_object* returnObj; 		/*Temporary returnobj can be reused */





	  	if (json_object_object_get_ex(jvalue, "Event", &returnObj))
	  	{
	  		strcpy(global_space_event[event_counter].Name,(char*)json_object_get_string(returnObj));
	  		//strncpy(temp_event->Name,(char*)json_object_get_string(returnObj),json_object_get_string(returnObj));
	  		//strcpy(events[event_counter]->Name,event_name) ;
	  	}
	  	if (json_object_object_get_ex(jvalue, "API_count", &returnObj))
	  	{
	  		global_space_event[event_counter].api_count = json_object_get_int(returnObj) ;

	  	}



	  	json_object *jarray_api; //temporary Json objects
	  	json_object *jarray_argument; //temporary Json objects


	  	/*Get API list*/
	  	json_object_object_get_ex(jvalue, "API_list",&jarray_api);
	  	if ( FALSE == jarray_api )
	  	    {
	  	        printf( "\"queries\" not found in JSON\n" );
	  	        return;
	  	    }
	  	key="API_list";
	  	const int arraylen2 = json_object_array_length(jarray_api); /*Getting the length of the array*/
	  	printf("Array Length: %dn",arraylen2);

	  	json_object * jvalue2;
	  	int j;
	  	//api *temp_api[arraylen2];
	  	global_space_event[event_counter].queueofapi = g_queue_new ();

	  	  for ( j=0; j< arraylen2; j++){/*List of API*/
	  		//api **temp_api = malloc(sizeof(api) * arraylen2);

	  	//	temp_api[j] = malloc(sizeof(api));
	  		jvalue2 = json_object_array_get_idx(jarray_api, j);
	  		json_object * returnObj;
	  		if (json_object_object_get_ex(jvalue2, "api_name", &returnObj))
	  			  					{
	  			  						strcpy(global_space_api[api_counter].api_name,json_object_get_string(returnObj)) ;
	  			  					}
	  		if (json_object_object_get_ex(jvalue2, "argument_count", &returnObj))
	  			  			{
	  			global_space_api[api_counter].argument_count= json_object_get_int(returnObj) ;


	  			json_object_object_get_ex(jvalue2, "args",&jarray_argument); /*Getting the array if it is a key value pair*/
	  			  		  	if ( FALSE == jarray_argument )
	  			  		  	    {
	  			  		  	        printf( "\"queries\" not found in JSON\n" );
	  			  		  	        return;
	  			  		  	    }
				key="args";
				int arraylen3 = json_object_array_length(jarray_argument); /*Getting the length of the array*/
				printf("Array Length: %dn",arraylen3);

				json_object * jvalue3;
				int k;
			    for ( k=0; k< arraylen3; k++){/*args list*/
					//targument *temp_argument;
					//temp_argument = malloc(sizeof(targument));

			    	jvalue3 = json_object_array_get_idx(jarray_argument, k);
						json_object * returnObj;
						if (json_object_object_get_ex(jarray_argument, "4", &returnObj))
										{
							global_space__argument[argument_counter].argument_number = json_object_get_int(jarray_argument) ;
										}

									if (json_object_object_get_ex(jarray_argument, "5", &returnObj))
										{
										strcpy(global_space__argument[argument_counter].value , json_object_get_string(returnObj)) ;
										}
									global_space_api[api_counter].argument_list = g_slist_append(global_space_api[api_counter].argument_list , &global_space__argument[argument_counter]);

									argument_counter++;
	  			  		  	  }

			    ///events->queueofapi =g_slist_append(events->queueofapi , temp_api);


			    		//g_queue_push_tail(events->queueofapi,temp_api[j]);

	  	}
	  		g_queue_push_tail(global_space_event[event_counter].queueofapi,&global_space_api[api_counter]);
	  					    api_counter++;

	  	  }
	  	Eventlist = g_slist_append(Eventlist , &global_space_event[event_counter]);
	  		  	    event_counter++;
	}
}


void my_custom_parser(json_object * jobj,char* key);
/*Parsing the json object*/
void json_parse_my(json_object * jobj ) {
  enum json_type type;
  json_object_object_foreach(jobj, key, val) { /*Passing through every array element*/
    printf("type: ",type);
    type = json_object_get_type(val);
    switch (type) {
      case json_type_boolean:
      case json_type_double:
      case json_type_int:

      case json_type_string: //print_json_value_my(val);


                           break;
      case json_type_object: printf("json_type_objectn");
                           jobj = json_object_object_get(jobj, key);
                           json_parse_my(jobj);
                           break;
      case json_type_array: printf("type: json_type_array, ");

                         json_parse_array_my(jobj, key);
                          break;
    }
  }
}





/**/

int main() {


	//match();
	//check_api_in_event_sequence("Sleep");
	//check_api_in_event_sequence("CreateFile");
	//check_api_in_event_sequence("NTCreateRemoteThread");
	//check_api_in_event_sequence("ResumeThread");

	//ParseJson("fuck.json");
	//char *string = "{\"Event_list\":[{\"Event\":\"Code Injection\",\"API_count\":5,\"API_list\":[{\"api_name\":\"Sleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"CreateFile\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NTCreateRemoteThread\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"ResumeThread\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]}]},{\"Event\":\"Cloning\",\"API_count\":5,\"API_list\":[{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]}]},{\"Event\":\"File open suspevious directory\",\"API_count\":5,\"API_list\":[{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]},{\"api_name\":\"NtSleep\",\"argument_count\":3,\"args\":[{\"4\":\"Arg4\"},{\"5\":\"arg5\"}]}]}]}";
	char *string ="{ \"Event_list\": [{ \"Event\": \"Code Injection\", \"API_count\": 4, \"API_list\": [ { \"api_name\": \"NtSleep\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"CreateRemoteThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"VirtualAlloc\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"ResumeThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"Anti Debug\", \"API_count\": 3, \"API_list\": [ { \"api_name\": \"IsDebuggerPresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" }, { \"7\": \"Arg7\" } ] }, { \"api_name\": \"Ntdsc\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"querysysteminfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"File open suspevious directory\", \"API_count\": 5, \"API_list\": [ { \"api_name\": \"CreateFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"WriteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"QueryFileInfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"DeleteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"isFilePresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] } ] } ";
	json_object * jobj = json_tokener_parse(string);
	if(jobj == NULL)
	{
		printf("dafd");
	}
	else
	{
		//my_custom_parser(jobj);
		//custom_parser(jobj);
		json_parse_my(jobj);
	}
	check_api_in_event_sequence("CreateFile");
	check_api_in_event_sequence("NtSleep");


		check_api_in_event_sequence("WriteFile");
		check_api_in_event_sequence("QueryFileInfo");
		check_api_in_event_sequence("CreateRemoteThread");
		check_api_in_event_sequence("DeleteFile");
		check_api_in_event_sequence("isFilePresent");
		check_api_in_event_sequence("VirtualAlloc");
		check_api_in_event_sequence("ResumeThread");
		//check_api_in_event_sequence("ResumeThread");
	//single_basic_parse(string, 0);
	return 0;
}
