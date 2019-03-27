var item = document.getElementById('delete_item')
var close = document.getElementById('close_deletion')
if(item){
  item.onclick = function(){
    document.getElementById('confirm_deletion').style.display = 'block';
  }
}
if(close){
  close.onclick = function(){
    document.getElementById('confirm_deletion').style.display = 'none';
  }
}
