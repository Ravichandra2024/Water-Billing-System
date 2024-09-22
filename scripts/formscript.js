document.querySelector('#hi').addEventListener('click', function(event) {
    event.preventDefault(); 
    var name = document.querySelector('#name').value;
    var id = document.querySelector('#id').value;
    var address = document.querySelector('#address').value;
    var phno = document.querySelector('#phno').value;

    if (name === '') {
        alert('Enter your name');
    } else if (id === '') {
        alert('Enter your water id');
    } else if (address === '') {
        alert('Enter your address');
    } else if (phno === '') {
        alert('Enter your phone number');
    } else {
        addForm(name, id, address, phno);
    }
});
function fun(){
    var name = document.querySelector('#name').value;
    var id = document.querySelector('#id').value;
    var address = document.querySelector('#address').value;
    var phno = document.querySelector('#phno').value;

    if (name === '') {
        alert('Enter your name');
    } else if (id === '') {
        alert('Enter your water id');
    } else if (address === '') {
        alert('Enter your address');
    } else if (phno === '') {
        alert('Enter your phone number');
    } else {
        addForm(name, id, address, phno);
    }
}
function addForm(name, id, address, phno) {
    
    var url = '/adddetails/'+name+'/'+id+'/'+address+'/'+'/'+phno
    console.log(url)
    fetch(url)
        .then(res => res.json())
        .then(data => {
            console.log(data)
            if (data.success) {
                alert("Data updated successfully");
               
                parent.window.location.href = '/dashboard';
            } else {
                alert('Failed to update the data');
            }
        })
        .catch(error => {
            console.error("Error:", error);
            alert('An error occurred while submitting the form');
        });
}
