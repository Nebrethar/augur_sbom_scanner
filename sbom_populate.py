import subprocess
import psycopg2
from subprocess import PIPE
import json
import re
import os
import requests

#class DoSOCSv2(object):
    #"""Uses the DoSOCSv2 database to return dataframes with interesting GitHub indicators"""

def parse_json(package_sx_1, package_sr_1, package_sr_3, package_cr_1, package_li_1, package_lc_1, cur, repo_id):
    license_information = {}

    temp_1 = {}
    for i in range(0, int(len(package_lc_1[0])/2)):
        j = i*2
        temp_1[package_lc_1[0][j]] = package_lc_1[0][j+1]

    coverage_temp = {**temp_1}

    temp_1 = {}
    for i in range(0, int(len(package_sx_1[0])/2)):
        j = i*2
        temp_1[package_sx_1[0][j]] = package_sx_1[0][j+1]

    spdx_temp = {**temp_1}

    temp_1 = {}
    for i in range(0, int(len(package_sr_1[0])/2)):
        j = i*2
        if package_sr_1[0][j] != '':
            temp_1[package_sr_1[0][j]] = package_sr_1[0][j+1]
    #print(package_sr_2)
    #print(package_sr_2[0])
    temp_3 = {}
    for i in range(0, int(len(package_sr_3[0])/2)):
        j = i*2
        temp_3[package_sr_3[0][j]] = package_sr_3[0][j+1]

    package_temp = {**temp_1, **temp_3}

    temp_1 = {}
    for i in range(0, int(len(package_cr_1[0])/2)):
        j = i*2
        temp_1[package_cr_1[0][j]] = package_cr_1[0][j+1]

    creation_temp = {**temp_1}

    #print(package_li_1)
    temp_2 = {}
    for g in range(0, int(len(package_li_1))):
        temp_1 = {}
        for i in range(0, int(len(package_li_1[g])/2)):
            j = i*2
            temp_1[package_li_1[g][j]] = package_li_1[g][j+1]
        temp_2["License Data " + str(g)] = temp_1

    license_temp = {**temp_2}

    license_information['Coverage'] = coverage_temp
    license_information['SPDX Data'] = spdx_temp
    license_information['Package'] = package_temp
    license_information['Creation'] = creation_temp
    license_information['Licenses'] = license_temp

    cur.execute("insert into augur_data.repo_sbom_scans(repo_id, sbom_scan) VALUES(" + str(repo_id)  + "," +  chr(39) + str(json.dumps(license_information)) + chr(39) + ");")

def grabreg(records, repo_id, dsfile):
    print("DETAILS FOUND. CREATING DOCUMENT")
    proc = subprocess.Popen("dosocs2 generate " + str(records[0][0]), shell=True, stdout=PIPE, stderr=PIPE)
    varerr = str(str(proc.stderr.read()).split(" ")[3])
    charvarerr = varerr.split("\\")[0]
    print("Document_id: " + str(charvarerr))
    #f = open("/home/sean/dosocs2/accessDB/scans-tv/" + repo_name + "-full.txt","w")
    #proc = subprocess.call("dosocs2 print " + str(charvarerr) + " -T 2.0.tag.coverage", shell=True, stdout=f, stderr=f)
    pope = subprocess.Popen("dosocs2 print " + str(charvarerr) + " -T " + dsfile, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = pope.communicate()
    #if out:
        #print(out)
    if err:
        print(err.decode('UTF-8'))
    #print (out)
    package_sx_1 = re.findall(r'(SPDXVersion): (.*)\n(DataLicense): (.*)\n(DocumentNamespace): (.*)\n(DocumentName): (.*)\n(SPDXID): (.*)\n(DocumentComment): (.*)\n', out.decode('UTF-8'))
    package_sr_1 = re.findall(r'(PackageName): (.*)\n(SPDXID): (.*)\n(PackageVersion|)? ?(.*|)\n?(PackageFileName): (.*)\n(PackageSupplier): (.*)\n(PackageOriginator): (.*)\n(PackageDownloadLocation): (.*)\n(PackageVerificationCode):? ?(.*|)\n?(PackageHomePage): (.*)\n(PackageLicenseConcluded):', out.decode('UTF-8'))
    package_sr_3 = re.findall(r'(PackageLicenseDeclared): (.*)\n(PackageLicenseComments): (.*)\n(PackageCopyrightText): (.*)\n(PackageSummary): (.*)\n(PackageDescription): (.*)\n(PackageComment): (.*|)', out.decode('UTF-8'))
    package_cr_1 = re.findall(r'(Creator): (.*)\n(Created): (.*)\n(CreatorComment): (.*)\n(LicenseListVersion): (.*)\n', out.decode('UTF-8'))
    package_li_1 = re.findall(r'(LicenseID): (.*)\n(LicenseName): (.*)\n(ExtractedText): (.*)\n(LicenseCrossReference): (.*)\n(LicenseComment): (.*)\n', out.decode('UTF-8'))
    package_lc_1 = re.findall(r'(TotalFiles): (.*)\n(DeclaredLicenseFiles): (.*)\n(PercentTotalLicenseCoverage): (.*)\n', out.decode('UTF-8'))
    return (package_sx_1, package_sr_1, package_sr_3, package_cr_1, package_li_1, package_lc_1)

def scan(dbname, user, password, host, port, dsfile, ipath):
    connection = psycopg2.connect(
        user = user,
        password = password,
        database = dbname,
        host = host,
        port = port,
    )
    print("********************")
    cur = connection.cursor()
    r = cur.execute("set search_path to augur_data; select repo_path, repo_id, repo_group_id, repo_name from repo order by repo_group_id;")
    rec = cur.fetchall()
    for sector in rec:
        print(sector)
        repo_id = sector[1]
        print("****************")
        print(repo_id)
        cur.execute("set search_path to spdx;")
        cur.execute("select sbom_scan from augur_data.repo_sbom_scans where repo_id = " + str(repo_id) + " LIMIT 1;")
        determin = cur.fetchall()
        if not determin:
            cur.execute("select dosocs_pkg_id from spdx.augur_repo_map where repo_id = " + str(repo_id) + " LIMIT 1;")
            records = cur.fetchall()
            print("****************")
            if records and records[0][0] != None:
                (package_sx_1, package_sr_1, package_sr_3, package_cr_1, package_li_1, package_lc_1) = grabreg(records, repo_id, dsfile)
                parse_json(package_sx_1, package_sr_1, package_sr_3, package_cr_1, package_li_1, package_lc_1, cur, repo_id)
                connection.commit()
            else:
                print("ERROR: RECORD DOES NOT EXIST IN MAPPING TABLE")
        else:
            print("DUPLICATE RECORD FOUND. SKIPPING")
    return
