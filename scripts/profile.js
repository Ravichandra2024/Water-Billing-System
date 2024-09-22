fetch('/fetch')
.then(res=>res.json())
.then(data=>{
    if(data.success){
        document.querySelector('#email').value=data.email;
        document.querySelector('#name').value=data.message.name;
        document.querySelector('#phno').value=data.message.phno;
        document.querySelector('#wid').value=data.message.waterid;
        document.querySelector('#add').value=data.message.address;
    }
    else{
        alert('Failed to fetch details')
    }
});
document.querySelector('#but').addEventListener('click',(eve)=>{
    x=document.querySelector('#name').value;
    y=document.querySelector('#phno').value;
    z=document.querySelector('#wid').value;
    a=document.querySelector('#add').value;
    if(x===''){
        alert('Enter you name');
    }
    else if(y===''){
        alert('Enter your phno');
    }
    else if(z===''){
        alert('Enter the water id');
    }
    else if(a===''){
        alert('Enter your address');
    }
    else{
        var url = '/adddetails/'+x+'/'+y+'/'+z+'/'+a;
        fetch(url)
        .then(res=>res.json())
        .then(data=>{
            if(data.success){
                alert('data updated successfully')
            }
            else{
                alert('Failed to update the data');
            }
        });
    }
});