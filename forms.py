from django import forms

from models import Blacklist_IP


class PostForm(forms.ModelForm):
    """
    form for submitting single IP ban
    """
    class Meta:
        model = Blacklist_IP
        fields = ('ip', 'blacklist_duration', 'reason', 'tag')
        widgets = {
            'ip': forms.TextInput(attrs={'placeholder': '127.168.000.000', 'class': 'form-control input-lg'}),
            'reason': forms.TextInput(
                attrs={'placeholder': 'Why is this IP banned?', 'class': 'form-control input-lg'}),
            'tag': forms.TextInput(
                attrs={'placeholder': 'Whatever you want to tag it as', 'class': 'form-control input-lg'}),
            'blacklist_duration': forms.TextInput(
                attrs={'placeholder': 'Defaults to -1 perma ban', 'class': 'form-control input-lg'}),
        }


class UploadFileForm(forms.ModelForm):
    """
    for for submitting a file BAN
    """
    class Meta:
        model = Blacklist_IP
        fields = ('file',)
