import boto3
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
import pandas as pd
import time
import sqlite3
import os

def correlate_security_groups(instances, group):
    # Correlate security group IDs with their corresponding instance IDs
    ec2_group_info = []  # Create a list to store security group info
    for instance in instances:
        security_groups = instance['security_groups']
        instance_name = instance['instance_name']
        ec2_group_info.append({
            'instance_name': instance_name,
            'security_groups': security_groups
        })
    allowed_ports = []

    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_security_groups()

    security_group_info = []
    for groups in response['SecurityGroups']:
        try:
            group_id = groups['GroupId']
            group_tags = groups['Tags']
            group_name = next((tag['Value'] for tag in group_tags if tag['Key'] == 'Name'), 'NA')
            security_group_info.append({
                'group_id': group_id,
                'group_name': group_name
            })
        except KeyError:
            # print()
            # print("No tags found for security group")
            # print(groups)
            # print()
            pass
        
    # # identify which instance is associated with which security group in allowed_ports
    correlated_security_group = []
    for allowed_ports in group['allowed_ports']:
        for sg in allowed_ports:
            group_id = sg['GroupID']
            if group_id != 'NA':
                instance_names = []
                for info in ec2_group_info:
                    if group_id in info['security_groups']:
                        #print(group_id)
                        #print(info['instance_name'])
                        instance_names.append(info['instance_name'])
                    else:
                        for group in security_group_info:
                            if group_id == group['group_id']:
                                if group['group_name'] not in instance_names:
                                    #print(group['group_name'])
                                    instance_names.append(group['group_name'])
                sg['Service or Instance'] = instance_names
            else:
                instance_names = []
                instance_names.append('NA')
                sg['Service or Instance'] = instance_names
            correlated_security_group.append(sg)
    return correlated_security_group

def get_open_ports(security_group_id):
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
    #print(response)
    security_group = response['SecurityGroups'][0]
    ip_permissions = security_group['IpPermissions']
    ip_permissions_egress = security_group['IpPermissionsEgress']
    allowed_ports = []
    
    for permission in ip_permissions:
        from_port = permission.get('FromPort', 'NA')
        to_port = permission.get('ToPort', 'NA')
        protocol = permission.get('IpProtocol', 'NA')
        ip_ranges = permission.get('IpRanges', [])
        user_id_group_pairs = permission.get('UserIdGroupPairs', [])
        if ip_ranges:
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp', 'NA')
                allowed_ports.append({
                    'Direction': 'Ingress',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IPRange': cidr_ip,
                    'GroupID': 'NA'
                })
        elif user_id_group_pairs:
            for user_id_group_pair in user_id_group_pairs:
                group_id = user_id_group_pair.get('GroupId', 'NA')
                allowed_ports.append({
                    'Direction': 'Ingress',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IPRange': 'NA',
                    'GroupID': group_id
                })

    for permission in ip_permissions_egress:
        from_port = permission.get('FromPort', 'NA')
        to_port = permission.get('ToPort', 'NA')
        protocol = permission.get('IpProtocol', 'NA')
        ip_ranges = permission.get('IpRanges', [])
        user_id_group_pairs = permission.get('UserIdGroupPairs', [])
        if ip_ranges:
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp', 'NA')
                allowed_ports.append({
                    'Direction': 'Egress',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IPRange': cidr_ip,
                    'GroupID': 'NA'
                })
        elif user_id_group_pairs:
            for user_id_group_pair in user_id_group_pairs:
                group_id = user_id_group_pair.get('GroupId', 'NA')
                allowed_ports.append({
                    'Direction': 'Egress',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IPRange': 'NA',
                    'GroupID': group_id
                })

    return allowed_ports

def get_instances():
    session = boto3.Session()
    ec2_client = session.client('ec2')
    response = ec2_client.describe_instances()
    instances = []

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            state = instance['State']['Name']
            tags = instance['Tags']
            instance_name = next((tag['Value'] for tag in tags if tag['Key'] == 'Name'), 'NA')
            private_ip = instance['PrivateIpAddress']
            groups = instance['SecurityGroups']
            security_groups = [sg['GroupId'] for sg in groups]
            allowed_ports = []

            for sg in security_groups:
               allowed_ports.append(get_open_ports(sg)) 
            try:
                public_ip = instance['PublicIpAddress']
            except KeyError:
                public_ip = 'NA'

            instances.append({
                'instance_id': instance_id,
                'state': state,
                'instance_name': instance_name,
                'private_ip': private_ip,
                'public_ip': public_ip, 
                'security_groups': security_groups,
                'allowed_ports': allowed_ports
            })

    return instances

def rotate_elastic_ip(instance_name, instance_id, public_ip):
    ec2_client = boto3.client('ec2')
    pub_ip = [public_ip]
    try:
        response = ec2_client.describe_addresses(PublicIps=pub_ip)
    except:
        st.write("No elastic IP found for : ", instance_name)
        return
    current_allocation_id = response['Addresses'][0]['AllocationId']
    #dissassociate elastic IP
    try:
        response_dissassociate = ec2_client.disassociate_address(PublicIp=public_ip)
    except:
        st.write("Not allowed to dissassociate IP for : ", instance_name)
        return
    #release current elastic IP
    response_release_ip = ec2_client.release_address(AllocationId=current_allocation_id)
    #allocate new elastic IP
    response_new_ip = ec2_client.allocate_address(Domain='vpc')['PublicIp']
    #associate new elastic IP
    response_associate = ec2_client.associate_address(PublicIp=response_new_ip, InstanceId=instance_id)
    #return new elastic IP
    store_public_ips(instance_name, response_new_ip)
    return response_new_ip

def restart_instance(instance_name, instance_id):
    ec2_client = boto3.client('ec2')
    # Restart the EC2 instance
    try:
        ec2_client.reboot_instances(InstanceIds=[instance_id])
    except:
        st.write("Unable to restart instance: ", instance_name)
        return

def create_database():
    if not os.path.exists('public_ips.db'):
        conn = sqlite3.connect('public_ips.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS public_ips 
                        (instance_name TEXT, public_ip TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()

def store_public_ips(instance_name, public_ip):
    conn = sqlite3.connect('public_ips.db')  # Connect to the SQLite database
    cursor = conn.cursor()
    print('connecting to DB')

    existing_ips = get_stored_public_ips(instance_name)  # Get existing IPs for instance name
    if public_ip not in existing_ips:
        print('storing ip in DB')
        print(instance_name)
        print(public_ip)
        cursor.execute("INSERT INTO public_ips (instance_name, ip) VALUES (?, ?)", (instance_name, public_ip))
    else:
        print("IP already exists in database")
        
    conn.commit()
    conn.close()

def get_stored_public_ips(instance_name):
    conn = sqlite3.connect('public_ips.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM public_ips WHERE instance_name = ?", (instance_name,))
    stored_ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return stored_ips

def download_csv(data):
    #print(data)
    df = pd.DataFrame(data)
    #print(df)
    csv_filename = 'ips_per_instance.csv'
    df.to_csv(csv_filename, index=False)
    #st.download_button('Download CSV', csv_filename)

def main():
    instances = get_instances()
    
    correlated_instances = []
    for instance in instances:
        instance_id = instance['instance_id']
        state = instance['state']
        instance_name = instance['instance_name']
        private_ip = instance['private_ip']
        public_ip = instance['public_ip']
        security_groups = instance['security_groups']
        allowed_ports = correlate_security_groups(instances, instance)
        correlated_instances.append({
            'instance_id': instance_id,
            'state': state,
            'instance_name': instance_name,
            'public_ip': public_ip,
            'private_ip': private_ip,
            'security_groups': security_groups,
            'allowed_ports': allowed_ports
        })

    streamlit_data = []
    for instance in instances:
        instance_id = instance['instance_id']
        instance_name = instance['instance_name']
        private_ip = instance['private_ip']
        public_ip = instance['public_ip']
        state = instance['state']
        #if public ip is not NA then store in database
        if public_ip != 'NA':
            store_public_ips(instance_name, public_ip)
        streamlit_data.append({
            'instance_name': instance_name,
            'public_ip': public_ip,
            'private_ip': private_ip, 
            'state': state,
            'instance_id': instance_id
        })
    
    #convert correlated_instances to dataframe
    df = pd.DataFrame(streamlit_data)

    gd = GridOptionsBuilder.from_dataframe(df)
    gd.configure_pagination(enabled=True)
    gd.configure_default_column(groupable=True, editable=True)
    #selection_mode = st.radio("Selection Mode", ['multiple'])
    #gd.configure_selection(selection_mode=selection_mode, use_checkbox=True)
    gd.configure_selection(selection_mode='multiple', use_checkbox=True)
    grid_options = gd.build()

    grid_table = AgGrid(
        df, 
        gridOptions=grid_options, 
        update_mode=GridUpdateMode.SELECTION_CHANGED, 
        allow_unsafe_jscode=True, 
        width='100%', 
        height='500px'
    )

    sel_row = grid_table['selected_rows']

    # add button to rotate IPs
    if st.button("Rotate IPs"):
        for i in sel_row:
            print(i['instance_name'])
            print(i['public_ip'])
            new_ip = rotate_elastic_ip(i['instance_name'],i['instance_id'], i['public_ip'])
            print(new_ip)
            #refresh AG Grid
        time.sleep(5)
        st.experimental_rerun()

    # add button to restart EC2 instances
    if st.button("Restart EC2 Instance(s)"):
        print("Restart Instance(s)")
        for i in sel_row:
            print(i['instance_name'])
            restart_instance(i['instance_name'],i['instance_id'])
        #refresh AG Grid
        time.sleep(5)
        st.experimental_rerun()

    # add button to restart EC2 instances
    if st.button("Show Egress/Ingress Ports"):
        print("Show Egress/Ingress Ports")
        for i in sel_row:
            st.write(i['instance_name'])
            for instance in correlated_instances:
                if i['instance_id'] == instance['instance_id']:
                    for rules in instance['allowed_ports']:
                        #import into pandas dataframe
                        df_rules = pd.DataFrame(rules)
                        st.write(df_rules)
    # add button to restart EC2 instances
    if st.button("Export IP History"):
        print("Export IP History")
        instance_names = [] 
        for i in sel_row:
            st.write(i['instance_name'])
            public_ips = get_stored_public_ips(i['instance_name'])
            instance_names.append({
                'instance_name': i['instance_name'],
                'public_ips': public_ips
                })
            if public_ips:
                for ips in public_ips:
                    st.write(ips)
            else:
                st.write("No IP history found for: ", instance_name)
        download_csv(instance_names)
        st.write("Results Saved to: %s/ips_per_instance.csv" % os.getcwd())

if __name__ == "__main__":
    create_database()
    main()
