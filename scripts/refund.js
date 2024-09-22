fetch('/refund')
.then(res=>res.json())
.then(data=>{
    if(data.success){
        alert('Generated successfully');
    }
    else{
        alert('Server problem')
    }
})