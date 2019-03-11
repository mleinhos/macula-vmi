/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#include <config.h>

#include <glib.h>
#include <gmodule.h>

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include "syscalls.h"
#include "winscproto.h"

#include <json-c/json.h>
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

/***********************************Date Structures**************************************/
#define MAX_LEN 256

typedef struct _argument{
	int argument_number;
	char value[MAX_LEN];
}targument,*argument;
typedef struct _API{
	char api_name[MAX_LEN];
	int argument_count;
	GSList* argument_list;
}api,*Papi;
typedef struct _Event {
	char event_name[MAX_LEN];
	GQueue *api_queue;
	int api_count;
}Event,*PEvent;

static GSList *Eventlist = NULL;  // Final List

static api *api_holder ;


static int init_check =0;


static void check_queue(gpointer opaque,  gpointer unused);
static void check_api_in_event_sequence(void *api_name);
//void check_queue(Event *event);
int match(void);

json_object *main_object;


static void sample(gpointer opaque, gpointer unused)
{
	api *myapi = (api*)opaque;
	char *api_name = (char*)unused ;
	//printf("%s",myapi->api_name);
}


static void check_queue(gpointer opaque,  gpointer unused)
{

	//printf("Event name is: %s",event->Name);
	Event *event =(Event*) opaque;
	char *api_name = (char*)unused ;
	//printf("%s : %s /n",api_name , event->event_name);
	//g_queue_foreach(event->queueofapi,sample,api_name);
	if (event->api_count == 0)
	{
		//return -1;
	}
	else
	{
		api *myapi = (api*)g_queue_peek_head(event->api_queue);
		//printf("%s : %s \n",api_name , myapi->api_name);
			if(strcmp(api_name,myapi->api_name)==0)
					{
						event->api_count--;
						if(event->api_count == 0)
								{
									printf("Event Triggered: %s",event->event_name);
									//return 0;
								}
					//	printf("%d\n",event->api_count);
						g_queue_pop_head (event->api_queue);
						//return 0;
					}

		//free(myapi);
	}


}


/*Test Function */


/*Check if API in any sequence*/
static void check_api_in_event_sequence(char *api_name){
	
	g_slist_foreach(Eventlist,check_queue,(gpointer)api_name);

}



void json_parse_my(json_object * jobj) ;



static int event_counter=0;
static int api_counter =0 ;
static int argument_counter=  0 ;

static Event *global_space_event;
static api *global_space_api ;
static targument *global_space__argument ;
static char *json_string ;
void json_parse_array_my( json_object *jobj, char *key) {
	global_space_api = (api*)malloc (sizeof(api) * 2048) ;
	global_space__argument = (targument*)malloc (sizeof(targument) * 2048);
	global_space_event = (Event*)malloc(sizeof(Event)*2048);

	void json_parse(json_object * jobj); /*Forward Declaration*/
	enum json_type type;

	json_object *jarray = jobj; /*Simply get the array*/

	if(key) {
    jarray = json_object_object_get(jobj, key); /*Getting the array if it is a key value pair*/
	}

	int arraylen = json_object_array_length(jarray); /*Getting the length of the array*/
	//printf("Array Length: %dn",arraylen);
	int i;

	json_object * jvalue;


	for (i=0; i< arraylen; i++){/*List of Events*/

		jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/

	  	json_object* returnObj; 		/*Temporary returnobj can be reused */





	  	if (json_object_object_get_ex(jvalue, "Event", &returnObj))
	  	{
	  		strcpy(global_space_event[event_counter].event_name,(char*)json_object_get_string(returnObj));
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
	  	//if ( FALSE == jarray_api )
	  	  //  {
	  	    //    printf( "\"queries\" not found in JSON\n" );
	  	     //   return;
	  	   // }
	  	key="API_list";
	  	const int arraylen2 = json_object_array_length(jarray_api); /*Getting the length of the array*/
	  	//printf("Array Length: %dn",arraylen2);

	  	json_object * jvalue2;
	  	int j;
	  	//api *temp_api[arraylen2];
	  	global_space_event[event_counter].api_queue = g_queue_new ();

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
	  		//	  		  	if ( FALSE == jarray_argument )
	  		//	  		  	    {
	  		//	  		  	        printf( "\"queries\" not found in JSON\n" );
	  		//	  		  	        return;
	  		//	  		  	    }
				key="args";
				int arraylen3 = json_object_array_length(jarray_argument); /*Getting the length of the array*/
				//printf("Array Length: %dn",arraylen3);

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
									//global_space_api[api_counter].argument_list = g_slist_append(global_space_api[api_counter].argument_list , &global_space__argument[argument_counter]);

									argument_counter++;
	  			  		  	  }

			    ///events->queueofapi =g_slist_append(events->queueofapi , temp_api);


			    		//g_queue_push_tail(events->queueofapi,temp_api[j]);

	  	}
	  		g_queue_push_tail(global_space_event[event_counter].api_queue,&global_space_api[api_counter]);
	  					    api_counter++;

	  	  }
	  	Eventlist = g_slist_append(Eventlist , &global_space_event[event_counter]);
	  		  	    event_counter++;
	}
}

void my_custom_parser(json_object * jobj,char* key);
/*Parsing the json object*/
void json_parse_my(json_object * jobj ) {
printf("json_object");
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



static event_response_t linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    syscalls* s = (syscalls*)info->trap->data;
    timeval t = get_time();

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("syscall," FORMAT_TIMEVAL ",%" PRIu32" 0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%s\n",
                   UNPACK_TIMEVAL(t), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->breakpoint.module, info->trap->name);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[SYSCALL] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" %s!%s\n",
                   UNPACK_TIMEVAL(t), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   info->trap->breakpoint.module, info->trap->name);
            break;
    }

    return 0;
}

static unicode_string_t* get_filename_from_handle(syscalls* s,
        drakvuf_t drakvuf,
        drakvuf_trap_info_t* info,
        addr_t handle)
{
    addr_t process = drakvuf_get_current_process(drakvuf, info->vcpu);

    if (!process)
        return NULL;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);
    if ( !obj )
        return NULL;

    return drakvuf_read_unicode(drakvuf, info, obj + s->object_header_body + s->file_object_filename);
}

static event_response_t win_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    if (init_check == 0)
	{
		init_check = 1;
	char * json_string =(char*) malloc(1000);
	json_string ="{ \"Event_list\": [ { \"Event\": \"Allocating Space\", \"API_count\": 4, \"API_list\": [ { \"api_name\":\"NtProtectVirtualMemory\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtAllocateVirtualMemory\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtOpenDirectoryObject\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtOpenSymbolicLinkObject\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] }, { \"Event\": \"Loading Dll\", \"API_count\": 5, \"API_list\": [ { \"api_name\":\"NtOpenFile\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtCreateSection\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtMapViewOfSection\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtQuerySection\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtClose\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] }, { \"Event\": \"Defeat ASLR\", \"API_count\": 5, \"API_list\": [ { \"api_name\":\"NtQueryInformationProcess\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtQueryVirtualMemory\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtOpenProcessToken\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtOpenKeyEx\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtOpenProcess\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtReadVirtualMemory\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"NtMapViewOfSection\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] } ] }";
	//json_string = "{ \"Event_list\": [ { \"Event\": \"Code Injection\", \"API_count\": 4, \"API_list\": [ { \"api_name\":\"NtSleep\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"CreateRemoteThread\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"VirtualAlloc\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"ResumeThread\", \"argument_count\":2, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] }, { \"Event\": \"Anti Debug\", \"API_count\": 3, \"API_list\": [ { \"api_name\":\"IsDebuggerPresent\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"}, {\"7\":\"Arg7\"} ] }, { \"api_name\":\"Ntdsc\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"querysysteminfo\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] }, { \"Event\": \"File open suspevious directory\", \"API_count\": 5, \"API_list\": [ { \"api_name\":\"CreateFile\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"WriteFile\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"QueryFileInfo\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"DeleteFile\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] }, { \"api_name\":\"isFilePresent\", \"argument_count\":3, \"args\":[ {\"4\":\"Arg4\"}, {\"5\":\"arg5\"} ] } ] } ] }";
	//json_string ="{ \"Event_list\": [{ \"Event\": \"Code Injection\", \"API_count\": 4, \"API_list\": [ { \"api_name\": \"NtSleep\", \"argument_count\": 2, \"args\":[{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"CreateRemoteThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"VirtualAlloc\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"ResumeThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"Anti Debug\", \"API_count\": 3, \"API_list\": [ { \"api_name\": \"IsDebuggerPresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" }, { \"7\": \"Arg7\" } ] }, { \"api_name\": \"Ntdsc\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"querysysteminfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"File open suspevious directory\", \"API_count\": 5, \"API_list\": [ { \"api_name\": \"CreateFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"WriteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"QueryFileInfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"DeleteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"isFilePresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] } ] } ";
//strcpy (json_string,"{ \"Event_list\": [{ \"Event\": \"Code Injection\", \"API_count\": 4, \"API_list\": [ { \"api_name\": \"NtSleep\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"CreateRemoteThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"VirtualAlloc\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"ResumeThread\", \"argument_count\": 2, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"Anti Debug\", \"API_count\": 3, \"API_list\": [ { \"api_name\": \"IsDebuggerPresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" }, { \"7\": \"Arg7\" } ] }, { \"api_name\": \"Ntdsc\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"querysysteminfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] }, { \"Event\": \"File open suspevious directory\", \"API_count\": 5, \"API_list\": [ { \"api_name\": \"CreateFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"WriteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"QueryFileInfo\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"DeleteFile\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] }, { \"api_name\": \"isFilePresent\", \"argument_count\": 3, \"args\": [{ \"4\": \"Arg4\" }, { \"5\": \"arg5\" } ] } ] } ] } ");
	json_object *myobj = json_tokener_parse(json_string);
	if(myobj == NULL)
	{
		printf("Can not Load Json");
	}
	else
	{
		//my_custom_parser(jobj);
		//custom_parser(jobj);
		//printf("fasdffffffffadsfad");
		json_parse_my(myobj);
	}
	}
    unsigned int i = 0, nargs = 0;
    size_t size = 0;
    unsigned char* buf = NULL; // pointer to buffer to hold argument values

    syscall_wrapper_t* wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls* s = wrapper->sc;
    const win_syscall_t* wsc = NULL;

    if (wrapper->syscall_index>-1 )
    {
        // need to malloc buf before setting type of each array cell
        wsc = &win_syscalls[wrapper->syscall_index];
        nargs = wsc->num_args;
        size = s->reg_size * nargs;
        buf = (unsigned char*)g_malloc(sizeof(char)*size);
    }

    uint32_t* buf32 = (uint32_t*)buf;
    uint64_t* buf64 = (uint64_t*)buf;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    timeval t;

    if ( nargs )
    {
        // get arguments only if we know how many to get

        if ( 4 == s->reg_size )
        {
            // 32 bit os
            ctx.addr = info->regs->rsp + s->reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, size, buf, NULL) )
                goto exit;
        }

        if ( 8 == s->reg_size )
        {
            if ( nargs > 0 )
                buf64[0] = info->regs->rcx;
            if ( nargs > 1 )
                buf64[1] = info->regs->rdx;
            if ( nargs > 2 )
                buf64[2] = info->regs->r8;
            if ( nargs > 3 )
                buf64[3] = info->regs->r9;
            if ( nargs > 4 )
            {
                // first 4 agrs passed via rcx, rdx, r8, and r9
                ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
                size_t sp_size = s->reg_size * (nargs-4);
                if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &(buf64[4]), NULL) )
                    goto exit;
            }
        }
    }

    t = get_time();
    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("syscall," FORMAT_TIMEVAL ",%" PRIu32" 0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%s",
                   UNPACK_TIMEVAL(t), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->breakpoint.module, info->trap->name);

            if ( nargs )
            {
                printf(",%" PRIu32,nargs);

                for ( i=0; i<nargs; i++ )
                {
                    addr_t val = 0;
                    printf(",%s,%s,%s,",win_arg_direction_names[wsc->args[i].dir],win_type_names[wsc->args[i].type],wsc->args[i].name);

                    if ( 4 == s->reg_size )
                    {
                        val = buf32[i];
                        printf("0x%" PRIx32",", buf32[i]);
                    }
                    else
                    {
                        val = buf64[i];
                        printf("0x%" PRIx64",", buf64[i]);
                    }

                    if ( wsc->args[i].dir == DIR_IN || wsc->args[i].dir == DIR_INOUT )
                    {
                        if ( wsc->args[i].type == PUNICODE_STRING)
                        {
                            unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);

                            if ( us )
                            {
                                printf("%s", us->contents);
                                vmi_free_unicode_str(us);
                            }
                        }

                        if ( !strcmp(wsc->args[i].name, "FileHandle") )
                        {
                            unicode_string_t* us = get_filename_from_handle(s, drakvuf, info, val);

                            if ( us )
                            {
                                printf("%s", us->contents);
                                vmi_free_unicode_str(us);
                            }
                        }
                    }

                    printf(",");
                }
            }

            printf("\n");
            break;
        default:
        case OUTPUT_DEFAULT:
           // printf("[SYSCALL] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" %s!%s",
            //       UNPACK_TIMEVAL(t), info->vcpu, info->regs->cr3, info->proc_data.name,
             //      USERIDSTR(drakvuf), info->proc_data.userid,
              //     info->trap->breakpoint.module, info->trap->name);
	
	    if(!strcmp(info->proc_data.name, "\\Device\\HarddiskVolume2\\Users\\test\\Desktop\\RemoteDLLInjector32.exe"))
	    {
		
		check_api_in_event_sequence((char*)info->trap->name);
	
	    }
	
            //*Args
    }
exit:
    g_free(buf);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static GSList* create_trap_config(drakvuf_t drakvuf, syscalls* s, symbols_t* symbols, const char* rekall_profile)
{

    GSList* ret = NULL;
    unsigned long i,j;

    PRINT_DEBUG("Received %lu symbols\n", symbols->count);

    if ( s->os == VMI_OS_WINDOWS )
    {
        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);

        if ( !ntoskrnl )
            return NULL;

        if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_HEADER", "Body", &s->object_header_body) )
            return NULL;
        if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_OBJECT", "FileName", &s->file_object_filename) )
            return NULL;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol* symbol = &symbols->symbols[i];

            if (strncmp(symbol->name, "Nt", 2))
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s\n", symbol->name);

            syscall_wrapper_t* wrapper = (syscall_wrapper_t*)g_malloc(sizeof(syscall_wrapper_t));

            wrapper->syscall_index = -1;
            wrapper->sc=s;

            for (j=0; j<NUM_SYSCALLS; j++)
            {
                if ( !strcmp(symbol->name,win_syscalls[j].name) )
                {
                    wrapper->syscall_index=j;
                    break;
                }
            }

            if ( wrapper->syscall_index==-1 )
                PRINT_DEBUG("[SYSCALLS]: %s not found in argument list\n", symbol->name);

            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 4;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ntoskrnl + symbol->rva;
            trap->breakpoint.module = "ntoskrnl.exe";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = win_cb;
            trap->data = wrapper;

            ret = g_slist_prepend(ret, trap);
        }
    }

    if ( s->os == VMI_OS_LINUX )
    {
        addr_t rva = 0;

        if ( !drakvuf_get_constant_rva(rekall_profile, "_text", &rva) )
            return NULL;

        addr_t kaslr = drakvuf_get_kernel_base(drakvuf) - rva;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol* symbol = &symbols->symbols[i];

            /* Looking for system calls */
            if (strncmp(symbol->name, "sys_", 4) )
                continue;

            /* This is the address of the table itself so skip it */
            if (!strcmp(symbol->name, "sys_call_table") )
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s at 0x%lx (kaslr 0x%lx)\n", symbol->name, symbol->rva + kaslr, kaslr);

            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 0;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = symbol->rva + kaslr;
            trap->breakpoint.module = "linux";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = linux_cb;
            trap->data = s;

            ret = g_slist_prepend(ret, trap);
        }
    }

    return ret;
}

static GHashTable* read_syscalls_filter(const char* filter_file)
{
    GHashTable* table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    if (!table) return NULL;

    FILE* f = fopen(filter_file, "r");
    if (!f)
    {
        g_hash_table_destroy(table);
        return NULL;
    }
    ssize_t read;
    do
    {
        char* line = NULL;
        size_t len = 0;
        read = getline(&line, &len, f);
        while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) read--;
        if (read > 0)
        {
            line[read] = '\0';
            g_hash_table_insert(table, line, NULL);
        }
        else
            free(line);
    }
    while (read != -1);

    fclose(f);
    return table;
}

static symbols_t* filter_symbols(const symbols_t* symbols, const char* filter_file)
{
    GHashTable* filter = read_syscalls_filter(filter_file);
    if (!filter) return NULL;
    symbols_t* ret = (symbols_t*)g_malloc0(sizeof(symbols_t));
    if (!ret)
    {
        g_hash_table_destroy(filter);
        return NULL;
    }

    ret->count = symbols->count;
    ret->symbols = (symbol_t*)g_malloc0(sizeof(symbol_t) * ret->count);
    if (!ret->symbols)
    {
        g_hash_table_destroy(filter);
        g_free(ret);
        return NULL;
    }

    size_t filtered_size = 0;
    for (size_t i = 0; i < symbols->count; ++i)
    {
        if (g_hash_table_contains(filter, symbols->symbols[i].name))
        {
            ret->symbols[filtered_size] = symbols->symbols[i];
            ret->symbols[filtered_size].name = g_strdup(symbols->symbols[i].name);
            filtered_size++;
        }
    }
    ret->count = filtered_size;
    g_hash_table_destroy(filter);
    return ret;
}

syscalls::syscalls(drakvuf_t drakvuf, const void* config, output_format_t output)
{
   //json_string

    const struct syscalls_config* c = (const struct syscalls_config*)config;
    symbols_t* symbols = drakvuf_get_symbols_from_rekall(c->rekall_profile);
    if (!symbols)
    {
        fprintf(stderr, "Failed to parse Rekall profile at %s\n", c->rekall_profile);
        throw -1;
    }

    if (c->syscalls_filter_file)
    {
        symbols_t* filtered_symbols = filter_symbols(symbols, c->syscalls_filter_file);
        drakvuf_free_symbols(symbols);
        if (!filtered_symbols)
        {
            fprintf(stderr, "Failed to apply syscalls filter %s\n", c->syscalls_filter_file);
            throw -1;
        }
        symbols = filtered_symbols;
    }

    this->os = drakvuf_get_os_type(drakvuf);
    this->traps = create_trap_config(drakvuf, this, symbols, c->rekall_profile);
    this->format = output;

    if ( !this->traps )
    {
        drakvuf_free_symbols(symbols);
        throw -1;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->reg_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    drakvuf_release_vmi(drakvuf);

    drakvuf_free_symbols(symbols);

    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;

        if ( !drakvuf_add_trap(drakvuf, trap) )
            throw -1;

        loop = loop->next;
    }
}

syscalls::~syscalls()
{
    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;
        g_free((char*)trap->name);
        if (trap->data != (void*)this)
        {
            g_free(trap->data);
        }
        g_free(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}
