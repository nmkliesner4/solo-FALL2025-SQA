'''
Akond Rahman 
Nov 15, 2020
Frequency: RQ2
'''
import numpy as np 
import os 
import pandas as pd 
import time 
import datetime 
import logging

# Basic logging setup so we capture progress and suspicious conditions from
# the reporting scripts. Use INFO for normal progress and WARNING for
# suspicious aggregate metrics that may warrant investigation.
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime( '%Y-%m-%d %H:%M:%S' ) 
  return strToret


def getAllSLOC(df_param, csv_encoding='latin-1' ):
    total_sloc = 0
    all_files = np.unique( df_param['FILE_FULL_PATH'].tolist() ) 
    for file_ in all_files:
        total_sloc = total_sloc + sum(1 for line in open(file_, encoding=csv_encoding))
    return total_sloc

def reportProportion( res_file, output_file ):
    # Log entry so operators can see when a proportion report run starts and
    # which input/output files are being used; useful during triage of
    # unexpected repo-level metrics.
    logger.info(f"reportProportion: starting report; res_file={res_file}, output_file={output_file}")
    res_df = pd.read_csv( res_file )
    repo_names   = np.unique( res_df['REPO_FULL_PATH'].tolist() )
    logger.info(f"reportProportion: found {len(repo_names)} repo(s) in results file")
    
    fields2explore = ['DATA_LOAD_COUNT', 'MODEL_LOAD_COUNT', 'DATA_DOWNLOAD_COUNT',	'MODEL_LABEL_COUNT', 'MODEL_OUTPUT_COUNT',	
                    'DATA_PIPELINE_COUNT', 'ENVIRONMENT_COUNT', 'STATE_OBSERVE_COUNT',  'TOTAL_EVENT_COUNT'
                    ]
    df_list = [] 
    
    for repo in repo_names:
        # Per-repo info logged at INFO so scans can be correlated across
        # multiple runs. Keep the original prints for console output.
        logger.info(f"reportProportion: processing repo={repo}")
        print('-'*50) 
        print(repo)
        repo_entity = res_df[res_df['REPO_FULL_PATH'] == repo ]           
        all_py_files   = np.unique( repo_entity['FILE_FULL_PATH'].tolist() )
        for field in fields2explore:
            field_atleast_one_df = repo_entity[repo_entity[field] > 0 ]
            atleast_one_files    = np.unique( field_atleast_one_df['FILE_FULL_PATH'].tolist() )
            prop_metric          = round(float(len( atleast_one_files ) )/float(len(all_py_files)) , 5) * 100
            # Log the computed proportion for this field. Keep existing
            # print statements for backward compatibility; logging is used by
            # monitoring/alerts for anomalous proportions.
            logger.info(f"reportProportion: repo={repo}, total_files={len(all_py_files)}, category={field}, atleast_one_files={len(atleast_one_files)}, prop_val={prop_metric}")
            # Emit warnings for suspicious aggregate values: no files (0%) or
            # nearly all files (>90%) containing the category may be worth
            # investigating for instrumentation errors or data issues.
            if prop_metric == 0:
                logger.warning(f"reportProportion: repo={repo}, category={field} has 0% files - possible missing instrumentation or absent feature")
            elif prop_metric > 90:
                logger.warning(f"reportProportion: repo={repo}, category={field} has very high coverage ({prop_metric}%) - verify it's expected")

            print('TOTAL_FILES:{}, CATEGORY:{}, ATLEASTONE:{}, PROP_VAL:{}'.format( len(all_py_files), field, len(atleast_one_files) , prop_metric  ))
            print('-'*50) 
            
            the_tup = ( repo, len(all_py_files), field, len(atleast_one_files), prop_metric )
            df_list.append( the_tup )
            
    CSV_HEADER = ['REPO_NAME', 'TOTAL_FILES', 'CATEGORY', 'ATLEASTONE', 'PROP_VAL']
    full_df = pd.DataFrame( df_list ) 
    full_df.to_csv(output_file, header= CSV_HEADER, index=False, encoding= 'utf-8') 


def reportEventDensity(res_file, output_file): 
    # Log start of the density report and inputs so monitoring can correlate
    # runs and detect unexpected or missing data sources.
    logger.info(f"reportEventDensity: starting report; res_file={res_file}, output_file={output_file}")
    res_df = pd.read_csv(res_file)
    repo_names = np.unique(res_df['REPO_FULL_PATH'].tolist())
    logger.info(f"reportEventDensity: found {len(repo_names)} repo(s) in results file")

    fields2explore = ['DATA_LOAD_COUNT', 'MODEL_LOAD_COUNT', 'DATA_DOWNLOAD_COUNT',	'MODEL_LABEL_COUNT', 'MODEL_OUTPUT_COUNT',	
                      'DATA_PIPELINE_COUNT', 'ENVIRONMENT_COUNT', 'STATE_OBSERVE_COUNT',  'TOTAL_EVENT_COUNT'
                     ]
  
    df_list = []
  
    for repo in repo_names:
        # Log per-repo processing so runs are traceable; keep prints for
        # backward-compatible console output.
        logger.info(f"reportEventDensity: processing repo={repo}")
        print('-'*50)
        print(repo)
        repo_entity = res_df[res_df['REPO_FULL_PATH'] == repo ]                         
        all_py_files   = np.unique( repo_entity['FILE_FULL_PATH'].tolist() )
        all_py_size    = getAllSLOC(repo_entity)
  

        for field in fields2explore:
            field_res_list  = repo_entity[field].tolist()
            field_res_count = sum(field_res_list)
            event_density   = round( float(field_res_count * 1000 ) / float(all_py_size)  , 5)
            # Log computed density so monitoring/alerting can pick up
            # anomalous values automatically.
            logger.info(f"reportEventDensity: repo={repo}, total_loc={all_py_size}, category={field}, total_event_count={field_res_count}, event_density={event_density}")
            # Heuristics to emit warnings: zero events (might indicate missing
            # instrumentation) or very high density (might indicate noisy
            # instrumentation or injected events). These are informational
            # and do not change function behavior.
            if field_res_count == 0:
                logger.warning(f"reportEventDensity: repo={repo}, category={field} has zero total events - possible missing instrumentation or absent feature")
            elif event_density > 100:
                logger.warning(f"reportEventDensity: repo={repo}, category={field} has high event density={event_density} per KLOC - verify expected")

            print('TOTAL_LOC:{}, CATEGORY:{}, TOTAL_EVENT_COUNT:{}, EVENT_DENSITY:{}'.format( all_py_size, field, field_res_count, event_density )  )
            print('-'*25)
            
            the_tup = ( repo, all_py_size, field, field_res_count, event_density )
            df_list.append( the_tup )
            
    CSV_HEADER = ['REPO_NAME', 'TOTAL_LOC', 'CATEGORY', 'TOTAL_EVENT_COUNT', 'EVENT_DENSITY']
    full_df = pd.DataFrame( df_list ) 
    full_df.to_csv(output_file, header= CSV_HEADER, index=False, encoding= 'utf-8') 

if __name__=='__main__': 
    print('*'*100 )
    t1 = time.time()
    print('Started at:', giveTimeStamp() )
    print('*'*100 )


    # DATASET_NAME = 'TEST'
    # RESULTS_FILE = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/ForensicsinML/Output/V5_OUTPUT_TEST.csv'

#     RESULTS_FILE = 'V5_OUTPUT_MODELZOO.csv' 
#     PROPORTION_FILE = 'PROPORTION_MODELZOO.csv'   
#     DENSITY_FILE = 'DENSITY_MODELZOO.csv' 
    
#     RESULTS_FILE = 'V5_OUTPUT_GITLAB.csv' 
#     PROPORTION_FILE = 'PROPORTION_GITLAB.csv'   
#     DENSITY_FILE = 'DENSITY_GITLAB.csv' 
     
#     RESULTS_FILE = 'V5_OUTPUT_GITHUB.csv' 
#     PROPORTION_FILE = 'PROPORTION_GITHUB.csv'   
#     DENSITY_FILE = 'DENSITY_GITHUB.csv'   
    
    reportProportion( RESULTS_FILE, PROPORTION_FILE )
    print('*'*100) 
    reportEventDensity( RESULTS_FILE, DENSITY_FILE )
    print('*'*100) 

    print('*'*100 )
    print('Ended at:', giveTimeStamp() )
    print('*'*100 )