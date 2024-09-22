fetch('/paid')
.then(res=>res.json())
.then(data=>{
    if(data.success){
        alert('Bill updated successfully');
    }
    else{
        alert('Server problem')
    }
})