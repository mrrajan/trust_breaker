use std::collections::HashMap;
use log::{info, error};
use crate::exhort::{ExhortResponse, Issues};
use crate::osv::{OSVResults, Vulnerability};

pub async fn compare_exhort_osvnvd(exhort: ExhortResponse, osv_nvd: Vec<OSVResults>, mut purl_with_vuln:HashMap<String, Option<Vec<Vulnerability>>>){
    info!("Comparing the results!");
    let exhort_dependencies = exhort.providers.osv.sources.osv.dependencies;
    for exh in exhort_dependencies{
        for ov in &osv_nvd{
            if exh.reference.clone() == ov.reference.clone(){
                purl_with_vuln.remove(&exh.reference.clone());
                compare_vuln(&exh.reference.clone(), exh.issues.clone(), ov.issues.clone());
                for exh_transitive in &exh.transitive.clone(){
                    for osv_transitive in &ov.transitive.clone().unwrap(){
                        if exh_transitive.reference == osv_transitive.reference{
                            purl_with_vuln.remove(&exh_transitive.reference.clone());
                            compare_vuln(&exh_transitive.reference, exh_transitive.issues.clone(), osv_transitive.vulnerabilities.clone());
                        }
                    }
                }
            }
        }
    }
    if purl_with_vuln.len() !=0{
        error!("The below package are not reported on the Exhort Report");
        error!("------------------------------------------------------------");
        for (purl,vuln) in purl_with_vuln{
            error!("Package {:?}: Vulnerabilities: {:?}", purl, vuln);
        }
        error!("------------------------------------------------------------");
    }
}

pub fn compare_vuln(purl: &str, exhort_direct_issues: Vec<Issues>, osv_direct_issues: Option<Vec<Vulnerability>>){
    let osv_issues = osv_direct_issues.unwrap();

    for ex_issue in &exhort_direct_issues{
        let mut found = false;
        for osv_issue in &osv_issues{
            if ex_issue.id == Some(osv_issue.id.clone()){
                found = true;
                break;
            }
        }
        if !found{
            error!("For PURL {:?}, Vulnerability {:?} not available in OSV, but reported on Exhort!", purl, ex_issue);
        }
    }
    for osv_issue in &osv_issues{
        let mut found = false;
        for ex_issue in &exhort_direct_issues{
            if ex_issue.id == Some(osv_issue.id.clone()){
                found = true;
                break;
            }
        }
        if !found{
            error!("For PURL {:?}, Vulnerability {:?} not available in Exhort, but available on OSV!",purl, osv_issue);
        }
    }
}