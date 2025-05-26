<script lang="ts">
	import DOMPurify from 'dompurify';

	import { onMount, getContext, createEventDispatcher, onDestroy } from 'svelte';
	import * as FocusTrap from 'focus-trap';
	import { subscriptionPurchase, SubscriptionPayments } from '$lib/apis/setmenu';
	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	import { fade } from 'svelte/transition';
	import { flyAndScale } from '$lib/utils/transitions';
	import alipayLogo from '$lib/assets/Alipay.png';
	import wechatLogo from '$lib/assets/Wechat.png';
	import { marked } from 'marked';
	export let menu;
	export let title = '';
	export let message = null;
	import { toast } from 'svelte-sonner';
	export let cancelLabel = $i18n.t('Cancel');
	export let confirmLabel = $i18n.t('Confirm');
	let qrCodeDataUrl = '';
	export let onConfirm = () => {};

	export let input = false;
	export let inputPlaceholder = '';
	export let inputValue = '';

	export let show = false;
	export let payType = 'alipay'; // "alipay" | "wechat"
	export let qrCodeUrl = {
		qrCodeUrl: '',
		trade_no: ''
	}; // 二维码图片地址

	export let onJump = () => {};

	let modalElement = null;
	let mounted = false;

	let focusTrap: FocusTrap.FocusTrap | null = null;

	const onPayTypeChange = (type: string) => {
		if (payType == type) {
			return;
		} else {
			payType = type;
			dinggou();
		}
	};

	const handleKeyDown = (event: KeyboardEvent) => {
		if (event.key === 'Escape') {
			console.log('Escape');
			show = false;
		}

		if (event.key === 'Enter') {
			console.log('Enter');
			confirmHandler();
		}
	};

	const confirmHandler = async () => {
		show = false;
		await onConfirm();
		dispatch('confirm', inputValue);
	};

	onMount(() => {
		mounted = true;
	});

	const dinggou = async () => {
		try {
			const res = await subscriptionPurchase(localStorage.token, menu.id, payType).catch(
				(error) => {
					toast.error(`${error}`);
					return null;
				}
			);

			if (res) {
				console.log('订购套餐', res.detail);
				qrCodeUrl.trade_no = res.id;
				if (res.detail.qrcode) {
					document.getElementById('trade-qrcode').innerHTML = '';
					new QRCode(document.getElementById('trade-qrcode'), {
						text: res.detail.qrcode,
						width: 128,
						height: 128,
						colorDark: '#000000',
						colorLight: '#ffffff',
						correctLevel: QRCode.CorrectLevel.H
					});
				} else {
					toast.error('未获取到支付链接，无法生成二维码');
					qrCodeUrl.qrCodeUrl = '';
				}
			}
		} catch (err) {
			console.error(err);
		}
	};

	$: if (menu) {
		dinggou();
		payType = 'alipay';
	}

	onDestroy(() => {
		show = false;
	});

	const ashuda = async () => {
		console.log('你好111111');
		try {
			const res = await SubscriptionPayments(localStorage.token, qrCodeUrl.trade_no).catch(
				(error) => {
					toast.error(`${error}`);
					return null;
				}
			);

			if (res) {
				console.log('获取订购套餐详情', res.detail);
			}
		} catch (err) {
			console.error(err);
		}
	};
</script>

{#if show}
	<!-- svelte-ignore a11y-click-events-have-key-events -->
	<!-- svelte-ignore a11y-no-static-element-interactions -->
	<div
		bind:this={modalElement}
		class=" fixed top-0 right-0 left-0 bottom-0 bg-black/60 w-full h-screen max-h-[100dvh] flex justify-center z-99999999 overflow-hidden overscroll-contain"
		on:mousedown={() => {
			show = false;
		}}
	>
		<div
			class=" m-auto rounded-2xl max-w-full w-[32rem] mx-2 bg-gray-50 dark:bg-gray-950 max-h-[100dvh] shadow-3xl"
			in:flyAndScale
			on:mousedown={(e) => {
				e.stopPropagation();
			}}
		>
			<div class="px-[1.75rem] py-6 flex flex-col">
				<div class=" text-lg font-semibold dark:text-gray-200 mb-2.5">
					{#if title !== ''}
						{title}
					{:else}
						{$i18n.t('Order Package')}
					{/if}
				</div>
				<div class="w-full max-w-md mx-auto rounded-2xl p-8">
					<div class="flex justify-between">
						<div class="text-lg font-bold mb-2">套餐名称：{menu.name}</div>
						<div class="text-lg font-bold mb-2">
							套餐额度： {menu.credits}积分<span class="text-base font-normal text-gray-500"
								>/{$i18n.t('day')}</span
							>
						</div>
					</div>
					<div class="text-3xl font-extrabold mb-4">
						<span class="text-lg font-bold">套餐价格：</span> ${menu.price}
						<span class="text-base font-normal text-gray-500"
							>/ {menu.duration}{$i18n.t('day')}</span
						>
					</div>

					<div class="text-center text-gray-700 font-medium mb-4">
						{$i18n.t('Please select a payment method')}
					</div>
					<div class="flex gap-4 mb-6">
						<div
							class="flex-1 border rounded-xl p-4 flex flex-col items-center cursor-pointer transition-all"
							class:bg-blue-50={payType === 'alipay'}
							class:border-blue-500={payType === 'alipay'}
							on:click={() => onPayTypeChange('alipay')}
						>
							<img src={alipayLogo} alt="Alipay" class="w-10 h-10 mb-2" />
							<div class="font-bold text-blue-600">{$i18n.t('Alipay')}</div>
							<div class="text-xs text-gray-400">Alipay payment</div>
						</div>
						<div
							class="flex-1 border rounded-xl p-4 flex flex-col items-center cursor-pointer transition-all"
							class:bg-green-50={payType === 'wxpay'}
							class:border-green-500={payType === 'wxpay'}
							on:click={() => onPayTypeChange('wxpay')}
						>
							<img src={wechatLogo} alt="WeChat Pay" class="w-10 h-10 mb-2" />
							<div class="font-bold text-green-600">{$i18n.t('WeChat')}</div>
							<div class="text-xs text-gray-400">WeChat Pay</div>
						</div>
					</div>
					<div class="text-blue-600 font-bold text-center mb-2">
						请使用{payType === 'alipay' ? '支付宝' : '微信'}扫码支付
					</div>
					<div class="text-xs text-gray-400 text-center mb-2">
						打开{payType === 'alipay' ? '支付宝' : '微信'}APP，扫一扫下方二维码
					</div>
					<div class="flex justify-center mb-2">
						<!-- <img
						src={qrCodeUrl.qrCodeUrl}
						alt="二维码"
						class="w-40 h-40 bg-white p-2 rounded-lg border"
					/> -->
						<div id="trade-qrcode" class="max-h-[128px] max-w-[128px]"></div>
					</div>
					<div class="text-center text-gray-700 mb-2">
						金额: <span class="font-bold">${menu.price}</span>
					</div>
					<div class=" text-gray-400 text-center cursor-pointer" on:click={ashuda}>
						支付后请点击此处手动刷新
					</div>
				</div>
			</div>
		</div>
	</div>
{/if}

<style>
	.modal-content {
		animation: scaleUp 0.1s ease-out forwards;
	}

	@keyframes scaleUp {
		from {
			transform: scale(0.985);
			opacity: 0;
		}
		to {
			transform: scale(1);
			opacity: 1;
		}
	}
</style>
