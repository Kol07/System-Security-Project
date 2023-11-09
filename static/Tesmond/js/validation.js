$(function()
  {
 var validator = $('#resetpw').validate(
      {
        rules:
        {
          newpw: {required:true,
                        regex:true}
        },
        messages:
        {
          newpw: {required:"Please enter a password", 
                      regex: "Password must contain at least 8 characters, 1 uppercase letter, 1 number and 1 special character"}        
        },
        errorPlacement: function(error, element) 
        {
            error.insertAfter( element.closest('.wrap-input100') );
         }
      });
    
    $.validator.addMethod(
        "regex",
        function(value, element, regexp) {
            var re = new RegExp(regexp);
            return this.optional(element) || re.test(value);
        },
        "Please check your input."
);
    
    $("#newpw").rules("add", { regex: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/ })
    
  });